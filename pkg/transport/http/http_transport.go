/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/trustbloc/aries-framework-go/pkg/transport"
	tlsCertPool "github.com/trustbloc/aries-framework-go/pkg/transport/http/tls"
)

const commContentType = "application/didcomm-envelope-enc"

// OutboundCommHTTP is the HTTP transport implementation of CommTransport
// it embeds an http.Server and has an http.Client instance
type OutboundCommHTTP struct {
	client *http.Client
	cfg    *OutboundCommConfig
}

// OutboundCommConfig are the HTTP client config used by OutboundCommHTTP
type OutboundCommConfig struct {
	Timeout      time.Duration
	CACertsPaths string
	caCertPool   tlsCertPool.CertPool
}

// NewOutboundCommFromConfig creates a new instance of CommHTTP to Post requests to other Agents
// To get a valid instance of OutboundCommHTTP, a cfg must be set
// if config is nil, this function will throw an error
func NewOutboundCommFromConfig(cfg *OutboundCommConfig) (*OutboundCommHTTP, error) {
	var cl *http.Client
	if cfg != nil {
		var err error
		cl, err = newHTTPClient(cfg)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("config is empty, cannot create new HTTP transport")
	}

	cm := &OutboundCommHTTP{
		client: cl,
		cfg:    cfg,
	}
	return cm, nil
}

// NewOutboundCommFromClient creates a new instance of CommHTTP to Post requests to other Agents
// To get a valid instance of OutboundCommHTTP, a client must be set
// if client is nil, this function will throw an error
func NewOutboundCommFromClient(client *http.Client) (*OutboundCommHTTP, error) {
	if client == nil {
		return nil, errors.New("client is empty, cannot create new HTTP transport")
	}

	cm := &OutboundCommHTTP{
		client: client,
	}
	return cm, nil
}

// Send sends a2a exchange data via HTTP (client side)
func (cs *OutboundCommHTTP) Send(data string, url string) (string, error) {
	resp, err := cs.client.Post(url, commContentType, bytes.NewBuffer([]byte(data)))
	if err != nil {
		log.Printf("HTTP Transport - Error posting did envelope to agent at [%s]: %v", url, err)
		return "", err
	}

	var respData string
	if resp != nil {
		isStatusSuccess := resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK
		if !isStatusSuccess {
			return "", errors.Errorf("Warning - Received non success POST HTTP status from agent at [%s]: status : %v", url, resp.Status)
		}
		// handle response
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(resp.Body)
		if err != nil {
			return "", err
		}
		respData = buf.String()
	}
	return respData, nil
}

// creates a new instance of HTTP transport as a client
func newHTTPClient(cfg *OutboundCommConfig) (*http.Client, error) {
	var err error
	var caCertPool tlsCertPool.CertPool
	if cfg.CACertsPaths != "" {
		caCertPool, err = tlsCertPool.NewCertPool(false)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create new Cert Pool")
		}

		caCertsPaths := strings.Split(cfg.CACertsPaths, ",")
		var caCerts []string
		for _, path := range caCertsPaths {
			if path == "" {
				continue
			}
			// Create a pool with server certificates
			caCert, e := ioutil.ReadFile(filepath.Clean(path))
			if e != nil {
				return nil, errors.Wrap(e, "Failed Reading server certificate")
			}
			caCerts = append(caCerts, string(caCert))
		}

		caCertPool.Add(tlsCertPool.DecodeCerts(caCerts)...)
	} else {
		caCertPool, err = tlsCertPool.NewCertPool(true)
		if err != nil {
			return nil, err
		}
	}

	// update the config's caCertPool
	cfg.caCertPool = caCertPool

	tlsConfig, err := buildNewCertPool(cfg.caCertPool)
	if err != nil {
		log.Printf("HTTP Transport - Failed to build/get Cert Pool: %s", err)
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: cfg.Timeout,
	}, nil
}

func buildNewCertPool(tlsCertPool tlsCertPool.CertPool) (*tls.Config, error) {
	cp, err := tlsCertPool.Get()
	if err != nil {
		return nil, err
	}
	// Create TLS configuration
	// add other agents (server) certs here.. for now we trust CA certs
	// Since this config cannot be manipulated once the client is created,
	// we must find a way to trust other agents here (or only trust root CAs).
	tlsConfig := &tls.Config{
		// if RootCAs is nil, client will use the host's root CA instead
		RootCAs:      cp,
		Certificates: nil,
	}
	return tlsConfig, nil
}

// DIDCommRequestHandler will create a new handler to enforce Did-Comm HTTP transport specs
// then routes processing to the passed in handler argument
func DIDCommRequestHandler(handler http.Handler, commHandler *transport.DIDCommHandler) http.Handler {

	validateHandler(commHandler)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case commHandler.ExchangeRequest.Path:
			processPOSTRequest(w, r, commHandler.ExchangeRequest.HandlerFunc)
			return
		case commHandler.ExchangeResponse.Path:
			processPOSTRequest(w, r, commHandler.ExchangeResponse.HandlerFunc)
			return
		case commHandler.IntroductionProposal.Path:
			processPOSTRequest(w, r, commHandler.IntroductionProposal.HandlerFunc)
			return
		case commHandler.IntroductionRequest.Path:
			processPOSTRequest(w, r, commHandler.IntroductionRequest.HandlerFunc)
			return
		case commHandler.IntroductionResponse.Path:
			processPOSTRequest(w, r, commHandler.IntroductionResponse.HandlerFunc)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

// TODO Log error message with common trustbloc/logger-lib
func processPOSTRequest(w http.ResponseWriter, r *http.Request, router func([]byte) error) {
	if valid := validMethodAndContentType(w, r); !valid {
		return
	}
	body, valid := validateAndGetPayload(r, w)
	if !valid {
		return
	}
	err := router(body)
	if err != nil {
		http.Error(w, "Error processing the request", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusAccepted)

}

// validateAndGetPayload validate and get the payload from the request
func validateAndGetPayload(r *http.Request, w http.ResponseWriter) ([]byte, bool) {
	if r.Body == nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return nil, false
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil || string(body) == "" {
		http.Error(w, "Error payload", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

// validMethodAndContentType validate HTTP method and content-type
func validMethodAndContentType(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-type")
	if ct != commContentType {
		http.Error(w, fmt.Sprintf("Unsupported Content-type \"%s\"", ct), http.StatusUnsupportedMediaType)
		return false
	}

	if r.Method != "POST" {
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func validateHandler(router *transport.DIDCommHandler) {
	validateRequestRouter(router.ExchangeRequest, "Exchange Request")
	validateRequestRouter(router.ExchangeResponse, "Exchange Response")
	validateRequestRouter(router.IntroductionProposal, "Introduction Proposal")
	validateRequestRouter(router.IntroductionRequest, "Introduction Request")
	validateRequestRouter(router.IntroductionResponse, "Introduction Response")
}

func validateRequestRouter(processor *transport.RequestRouter, handlerType string) {
	if processor == nil || processor.Path == "" || processor.HandlerFunc == nil {
		panic("Missing mandatory path and handler function for " + handlerType)
	}
}
