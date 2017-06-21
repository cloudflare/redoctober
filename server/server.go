// Package server contains the server code for Red October.
//
// Copyright (c) 2013 CloudFlare, Inc.
package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/cloudflare/redoctober/core"
	"github.com/cloudflare/redoctober/report"
	"github.com/coreos/go-systemd/activation"
)

// DefaultIndexHtml can be used to customize the package default index page
// when static path is not specified
var DefaultIndexHtml = ""

var functions = map[string]func([]byte) ([]byte, error){
	"/create":          core.Create,
	"/create-user":     core.CreateUser,
	"/summary":         core.Summary,
	"/purge":           core.Purge,
	"/delegate":        core.Delegate,
	"/password":        core.Password,
	"/encrypt":         core.Encrypt,
	"/re-encrypt":      core.ReEncrypt,
	"/decrypt":         core.Decrypt,
	"/owners":          core.Owners,
	"/modify":          core.Modify,
	"/export":          core.Export,
	"/order":           core.Order,
	"/orderout":        core.OrdersOutstanding,
	"/orderinfo":       core.OrderInfo,
	"/ordercancel":     core.OrderCancel,
	"/restore":         core.Restore,
	"/reset-persisted": core.ResetPersisted,
	"/status":          core.Status,
}

type userRequest struct {
	rt string // The request type (which will be one of the
	// keys of the functions map above
	in []byte // Arbitrary input data (depends on the core.*
	// function called)
	resp chan<- []byte // Channel down which a response is sent (the
	// data sent will depend on the core.* function
	// called to handle this request)
}

// processRequest handles a single request receive on the JSON API for
// one of the functions named in the functions map above.
func processRequest(requestType string, w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Content-Type", "application/json")
	header.Set("Strict-Transport-Security", "max-age=86400; includeSubDomains; preload")

	tags := map[string]string{
		"request-type": requestType,
		"request-from": r.RemoteAddr,
	}
	fn, ok := functions[requestType]
	if !ok {
		err := errors.New("redoctober: unknown request for " + requestType)
		report.Check(err, tags)
		http.Error(w, "Unknown request", http.StatusInternalServerError)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		report.Check(err, tags)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := fn(body)
	if err != nil {
		// The function should also report errors in more detail.
		report.Check(err, tags)
		log.Printf("http.main failed: %s: %s", requestType, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(resp)
}

// NewServer starts an HTTPS server the handles the redoctober JSON
// API. Each of the URIs in the functions map above is setup with a
// separate HandleFunc. Each HandleFunc is an instance of queueRequest
// above.
//
// Returns a valid http.Server handling redoctober JSON requests (and
// its associated listener) or an error
func NewServer(staticPath, addr, caPath string, certPaths, keyPaths []string, useSystemdSocket bool) (*http.Server, net.Listener, error) {
	config := &tls.Config{
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
	}
	for i, certPath := range certPaths {
		cert, err := tls.LoadX509KeyPair(certPath, keyPaths[i])
		if err != nil {
			return nil, nil, fmt.Errorf("Error loading certificate (%s, %s): %s", certPath, keyPaths[i], err)
		}
		config.Certificates = append(config.Certificates, cert)
	}
	config.BuildNameToCertificate()

	// If a caPath has been specified then a local CA is being used
	// and not the system configuration.

	if caPath != "" {
		pemCert, err := ioutil.ReadFile(caPath)
		if err != nil {
			return nil, nil, fmt.Errorf("Error reading %s: %s\n", caPath, err)
		}

		derCert, _ := pem.Decode(pemCert)
		if derCert == nil {
			return nil, nil, fmt.Errorf("No PEM data was found in the CA certificate file\n")
		}

		cert, err := x509.ParseCertificate(derCert.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("Error parsing CA certificate: %s\n", err)
		}

		rootPool := x509.NewCertPool()
		rootPool.AddCert(cert)

		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = rootPool
	}

	var lstnr net.Listener
	if useSystemdSocket {
		listenFDs, err := activation.Listeners(true)
		if err != nil {
			log.Fatal(err)
		}
		if len(listenFDs) != 1 {
			log.Fatalf("Unexpected number of socket activation FDs! (%d)", len(listenFDs))
		}
		lstnr = tls.NewListener(listenFDs[0], config)
	} else {
		conn, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("Error starting TCP listener on %s: %s\n", addr, err)
		}

		lstnr = tls.NewListener(conn, config)

	}
	mux := http.NewServeMux()

	// queue up post URIs
	for current := range functions {
		// copy this so reference does not get overwritten
		requestType := current
		mux.HandleFunc(requestType, func(w http.ResponseWriter, r *http.Request) {
			log.Printf("http.server: endpoint=%s remote=%s", requestType, r.RemoteAddr)
			processRequest(requestType, w, r)
		})
	}

	// queue up web frontend
	idxHandler := &indexHandler{staticPath}
	mux.HandleFunc("/index", idxHandler.handle)
	mux.HandleFunc("/", idxHandler.handle)

	srv := http.Server{
		Addr:         addr,
		Handler:      mux,
		TLSConfig:    config,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}

	return &srv, lstnr, nil
}

type indexHandler struct {
	staticPath string
}

func (this *indexHandler) handle(w http.ResponseWriter, r *http.Request) {
	var body io.ReadSeeker
	var tags = map[string]string{}

	if this.staticPath != "" {
		tags["static-path"] = this.staticPath
		f, err := os.Open(this.staticPath)
		if err != nil {
			report.Check(err, tags)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		body = f
	} else {
		body = bytes.NewReader([]byte(DefaultIndexHtml))
	}

	header := w.Header()
	header.Set("Content-Type", "text/html")
	header.Set("Strict-Transport-Security", "max-age=86400; includeSubDomains; preload")
	// If the server isn't HTTPS worthy, the HSTS header won't be honored.

	http.ServeContent(w, r, "index.html", time.Now(), body)
}
