/*
	Copyright SecureKey Technologies Inc. All Rights Reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type httpTestCase struct {
	name         string
	httpMethod   string
	url          string
	contentType  string
	failHTTPPost bool
	sendUrl      string
	sendPayload  string
	failSend     bool
}

var testHandler http.Handler
var oCommHTTPClient *OutboundCommHTTP

const certPrefix = "test/fixtures/certs/"
const certPoolsPaths = certPrefix + "ec-pubCert1.pem," + certPrefix + "ec-pubCert2.pem," + certPrefix + "ec-pubCert3.pem,"
const clientTimeout = 10 * time.Second

func TestHTTPTransport(t *testing.T) {
	// test wrong/bad handler requests and finally a passing test case
	tcs := []httpTestCase{
		{
			name:         "Fail: Empty HTTP method and content type",
			httpMethod:   "",
			url:          "/",
			contentType:  "",
			failHTTPPost: true,
		},
		{
			name:         "Fail: Empty content type",
			httpMethod:   "POST",
			url:          "/",
			contentType:  "",
			failHTTPPost: true,
		},
		{
			name:         "Fail: Empty HTTP method",
			httpMethod:   "",
			url:          "/",
			contentType:  commContentType,
			failHTTPPost: true,
		},
		{
			name:         "Fail: bad url, content not found",
			httpMethod:   "POST",
			url:          "/badurl",
			contentType:  commContentType,
			failHTTPPost: true,
		},
		{
			name:         "Pass - valid POST request",
			httpMethod:   "POST",
			url:          "/",
			contentType:  commContentType,
			failHTTPPost: false,
			sendUrl:      "https://localhost:8090",
			sendPayload:  "test",
			failSend:     false,
		},
		{
			name:         "Send Fail - valid POST request but invalid Send call",
			httpMethod:   "POST",
			url:          "/",
			contentType:  commContentType,
			failHTTPPost: false,
			sendUrl:      "https://badurl",
			sendPayload:  "test",
			failSend:     true,
		},
		{
			name:         "Send Fail - valid POST request and Send() URL but with bad payload",
			httpMethod:   "POST",
			url:          "/",
			contentType:  commContentType,
			failHTTPPost: false,
			sendUrl:      "https://localhost:8090",
			sendPayload:  "bad",
			failSend:     true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// test HTTPHandler
			req, err := http.NewRequest(tc.httpMethod, tc.url, nil)
			require.NoError(t, err, "unexpected error")
			req.Header.Set("Content-type", tc.contentType)

			rr := httptest.NewRecorder()
			testHandler.ServeHTTP(rr, req)

			if !tc.failHTTPPost {
				require.Equal(t, http.StatusAccepted, rr.Code)

				err = oCommHTTPClient.Send(tc.sendPayload, tc.sendUrl)
				if tc.failSend {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			}
		})
	}
}

type mockHttpHandler struct {
}

func (m mockHttpHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	mockHandlingRoute(res, req)
}

func mockHandlingRoute(res http.ResponseWriter, req *http.Request) {
	if req.Body != nil {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil || string(body) == "bad" {
			res.WriteHeader(http.StatusBadRequest)
			res.Write([]byte(fmt.Sprintf("bad request: %s", body)))
			return
		}
	}

	// mocking successful response
	res.WriteHeader(http.StatusAccepted) // usually DID-Comm expects StatusAccepted code (202)
	res.Write([]byte("success"))
}

func TestMain(m *testing.M) {
	testHandler = DidCommHandler(mockHttpHandler{})
	httpServer := &http.Server{
		Addr:    ":8090",
		Handler: testHandler,
	}

	oCommConfig := &OutboundCommConfig{
		Timeout:      clientTimeout,
		CACertsPaths: certPoolsPaths,
	}
	var err error
	oCommHTTPClient, err = NewOutboundCommFromConfig(oCommConfig)
	if err != nil {
		log.Fatalf("Failed to create an OutboundComm client: %s", err)
	}

	go httpServer.ListenAndServeTLS(certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
	rc := m.Run()
	err = httpServer.Close()
	if err != nil {
		log.Fatalf("Failed to stop server: %s, integration test results: %d", err, rc)
	}
	os.Exit(rc)
}

type outboundClientTestCase struct {
	name               string
	outboundCommConfig *OutboundCommConfig
	httpClient         *http.Client
	url                string
	fail               bool
}

func TestNewOutboundComm(t *testing.T) {
	tcs := []outboundClientTestCase{
		{
			name: "Fail: Config and HTTP client nil",
			fail: true,
		},
		{
			name: "Fail: Config has wrong server Certs path",
			fail: true,
			outboundCommConfig: &OutboundCommConfig{
				Timeout:      10 * time.Second,
				CACertsPaths: "badpath",
			},
		},
		{
			name: "Pass: Config has empty server Certs - will use system cert pool",
			fail: false,
			outboundCommConfig: &OutboundCommConfig{
				Timeout: 10 * time.Second,
			},
		},
		{
			name:       "Pass: passing in HTTP client instead of config",
			fail:       false,
			httpClient: &http.Client{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var oc *OutboundCommHTTP
			var err error
			if tc.httpClient != nil {
				oc, err = NewOutboundCommFromClient(tc.httpClient)
				require.NoError(t, err)
			} else if tc.outboundCommConfig != nil {
				oc, err = NewOutboundCommFromConfig(tc.outboundCommConfig)
				if tc.outboundCommConfig.CACertsPaths == "badpath" {
					require.EqualError(t, err, "Failed Reading server certificate: open badpath: no such file or directory")
					require.Nil(t, oc)
					return
				}
				require.NoError(t, err)
			} else if tc.fail {
				oc, err = NewOutboundCommFromClient(nil)
				require.EqualError(t, err, "client is empty, cannot create new HTTP transport")
				require.Nil(t, oc)
				oc, err = NewOutboundCommFromConfig(nil)
				require.EqualError(t, err, "config is empty, cannot create new HTTP transport")
				require.Nil(t, oc)
				return
			}

			require.NotNil(t, oc)
		})
	}

}
