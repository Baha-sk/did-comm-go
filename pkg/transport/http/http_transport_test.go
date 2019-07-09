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
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/aries-framework-go/pkg/transport"
)

type httpTestCase struct {
	name           string
	httpMethod     string
	url            string
	contentType    string
	failHTTPPost   bool
	sendUrl        string
	sendPayload    string
	failSend       bool
	respData       string
	expectedStatus int
}

var testHandler http.Handler
var oCommHTTPClient *OutboundCommHTTP

const certPrefix = "../../../test/fixtures/keys/"
const certPoolsPaths = certPrefix + "ec-pubCert1.pem," + certPrefix + "ec-pubCert2.pem," + certPrefix + "ec-pubCert3.pem,"
const clientTimeout = 10 * time.Second
const exchangeRequest = "/exchange-request"
const exchangeResponse = "/exchange-response"

func TestHTTPTransport(t *testing.T) {
	// test wrong/bad handler requests and finally a passing test case
	tcs := []httpTestCase{
		{
			name:           "Fail: bad url, content not found",
			httpMethod:     "POST",
			url:            "/badurl",
			contentType:    commContentType,
			failHTTPPost:   true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Pass - valid POST request",
			httpMethod:     "POST",
			url:            "/",
			contentType:    commContentType,
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090",
			sendPayload:    "test",
			failSend:       false,
			respData:       "success",
			expectedStatus: http.StatusAccepted,
		},
		{
			name:           "Send Fail - valid POST request but invalid Send call",
			httpMethod:     "POST",
			url:            "/",
			contentType:    commContentType,
			failHTTPPost:   true,
			sendUrl:        "https://badurl",
			sendPayload:    "test",
			failSend:       true,
			respData:       "success",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Send Fail - valid POST request and Send() URL but with bad payload",
			httpMethod:     "POST",
			url:            "/",
			contentType:    commContentType,
			failHTTPPost:   true,
			sendUrl:        "https://localhost:8090",
			sendPayload:    "bad",
			failSend:       true,
			respData:       "success",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Send Exchange Request",
			httpMethod:     "POST",
			url:            exchangeRequest,
			contentType:    commContentType,
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090" + exchangeRequest,
			sendPayload:    "valid",
			failSend:       false,
			respData:       "",
			expectedStatus: http.StatusAccepted,
		},
		{
			name:           "Send Exchange Request - invalid request payload",
			httpMethod:     "POST",
			url:            exchangeRequest,
			contentType:    commContentType,
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090" + exchangeRequest,
			sendPayload:    "invalid",
			failSend:       true,
			respData:       "",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "Send Exchange Response",
			httpMethod:     "POST",
			url:            exchangeResponse,
			contentType:    commContentType,
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090" + exchangeResponse,
			sendPayload:    "bad",
			failSend:       false,
			respData:       "",
			expectedStatus: http.StatusAccepted,
		},
		{
			name:           "Send Exchange Request - invalid HTTP Method",
			httpMethod:     "GET",
			url:            exchangeRequest,
			contentType:    commContentType,
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090" + exchangeRequest,
			sendPayload:    "bad",
			failSend:       false,
			respData:       "",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Send Exchange Request - Empty payload",
			httpMethod:     "POST",
			url:            exchangeRequest,
			contentType:    commContentType,
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090" + exchangeRequest,
			sendPayload:    "",
			failSend:       true,
			respData:       "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Send Exchange Request - Nil payload",
			httpMethod:     "POST",
			url:            exchangeRequest,
			contentType:    commContentType,
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090" + exchangeRequest,
			failSend:       true,
			respData:       "",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Send Exchange Request - Invalid content type",
			httpMethod:     "POST",
			url:            exchangeRequest,
			contentType:    "abc",
			failHTTPPost:   false,
			sendUrl:        "https://localhost:8090" + exchangeRequest,
			failSend:       true,
			respData:       "",
			expectedStatus: http.StatusUnsupportedMediaType,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			// test HTTPHandler
			req, err := http.NewRequest(tc.httpMethod, tc.url, strings.NewReader(tc.sendPayload))
			require.NoError(t, err, "unexpected error")
			req.Header.Set("Content-type", tc.contentType)

			rr := httptest.NewRecorder()
			testHandler.ServeHTTP(rr, req)

			if !tc.failHTTPPost {
				require.Equal(t, tc.expectedStatus, rr.Code)

				respData, err := oCommHTTPClient.Send(tc.sendPayload, tc.sendUrl)
				if tc.failSend {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.respData, respData)
			}
		})
	}

	require.Panics(t, func() { DIDCommRequestHandler(mockHttpHandler{}, &transport.DIDCommHandler{}) },
		"The code did not panic without mandatory path/handlers")
}

type mockHttpHandler struct {
}

func (m mockHttpHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	mockHandlingRoute(res, req)
}

func mockHandlingRoute(res http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/badurl" {
		res.WriteHeader(http.StatusBadRequest)
		return
	}

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
	exchangeHandler := &transport.DIDCommHandler{
		ExchangeRequest: &transport.RequestRouter{Path: exchangeRequest, HandlerFunc: func(payload []byte) error {
			if string(payload) == "invalid" {
				return errors.New("Invalid payload")
			}
			return nil
		}},
		ExchangeResponse: &transport.RequestRouter{Path: exchangeResponse, HandlerFunc: func(payload []byte) error {
			return nil
		}},
	}

	testHandler = DIDCommRequestHandler(mockHttpHandler{}, exchangeHandler)
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

	go func() {
		err := httpServer.ListenAndServeTLS(certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
		if err != nil && err.Error() != "http: Server closed" {
			log.Fatalf("HTTP server failed to start: %v", err)
		}
	}()

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
