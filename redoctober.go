// Package redoctober contains the server code for Red October.
//
// Copyright (c) 2013 CloudFlare, Inc.

package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cloudflare/redoctober/core"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
)

// List of URLs to register and their related functions

var functions = map[string]func([]byte) ([]byte, error){
	"/create":   core.Create,
	"/summary":  core.Summary,
	"/delegate": core.Delegate,
	"/password": core.Password,
	"/encrypt":  core.Encrypt,
	"/decrypt":  core.Decrypt,
	"/modify":   core.Modify,
}

type userRequest struct {
	rt string // The request type (which will be one of the
	// keys of the functions map above
	in []byte // Arbitrary input data (depends on the core.*
	// function called)
	resp chan []byte // Channel down which a response is sent (the
	// data sent will depend on the core.* function
	// called to handle this request)
}

// queueRequest handles a single request receive on the JSON API for
// one of the functions named in the functions map above. It reads the
// request and sends it to the goroutine started in main() below for
// processing and then waits for the response.
func queueRequest(process chan userRequest, requestType string, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make(chan []byte)
	process <- userRequest{rt: requestType, in: body, resp: response}

	if resp, ok := <-response; ok {
		w.Write(resp)
	} else {
		http.Error(w, "Unknown request", http.StatusInternalServerError)
	}
}

// NewServer starts an HTTPS server the handles the redoctober JSON
// API. Each of the URIs in the functions map above is setup with a
// separate HandleFunc. Each HandleFunc is an instance of queueRequest
// above.
//
// Returns a valid http.Server handling redoctober JSON requests (and
// its associated listener) or an error
func NewServer(process chan userRequest, staticPath, addr, certPath, keyPath, caPath string) (*http.Server, *net.Listener, error) {
	mux := http.NewServeMux()
	srv := http.Server{
		Addr:    addr,
		Handler: mux,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("Error loading certificate (%s, %s): %s", certPath, keyPath, err)
	}

	config := tls.Config{
		Certificates: []tls.Certificate{cert},
		Rand:         rand.Reader,
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
	}

	// If a caPath has been specified then a local CA is being used
	// and not the system configuration.

	if caPath != "" {
		rootPool := x509.NewCertPool()
		pemCert, err := ioutil.ReadFile(caPath)
		if err != nil {
			return nil, nil, fmt.Errorf("Error reading %s: %s\n", caPath, err)
		}
		derCert, pemCert := pem.Decode(pemCert)
		if derCert == nil {
			return nil, nil, fmt.Errorf("Error decoding CA certificate: %s\n", err)
		}
		cert, err := x509.ParseCertificate(derCert.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("Error parsing CA certificate: %s\n", err)
		}

		rootPool.AddCert(cert)
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = rootPool
	}

	conn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("Error starting TCP listener on %s: %s\n", addr, err)
	}

	lstnr := tls.NewListener(conn, &config)

	// queue up post URIs
	for current := range functions {
		// copy this so reference does not get overwritten
		var requestType = current
		mux.HandleFunc(requestType, func(w http.ResponseWriter, r *http.Request) {
			queueRequest(process, requestType, w, r)
		})
	}

	// queue up web frontend
	if staticPath != "" {
		mux.HandleFunc("/index", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, staticPath)
		})
	}

	return &srv, &lstnr, nil
}

const usage = `Usage:

	redoctober -static <path> -vaultpath <path> -addr <addr> -cert <path> -key <path> [-ca <path>]

example:
redoctober -vaultpath /tmp/diskrecord.json -addr localhost:8080 -cert cert.pem -key cert.key
`

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	var staticPath = flag.String("staticpath", "/tmp/index.html", "Path to the the static entry")
	var vaultPath = flag.String("vaultpath", "/tmp/tmpvault", "Path to the the disk vault")
	var addr = flag.String("addr", "localhost:8000", "Server and port separated by :")
	var certPath = flag.String("cert", "", "Path of TLS certificate in PEM format")
	var keyPath = flag.String("key", "", "Path of TLS private key in PEM format")
	var caPath = flag.String("ca", "", "Path of TLS CA for client authentication (optional)")
	flag.Parse()

	if *vaultPath == "" || *addr == "" || *certPath == "" || *keyPath == "" {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	if err := core.Init(*vaultPath); err != nil {
		log.Fatalf(err.Error())
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// The core package is not safe to be shared across goroutines so
	// this supervisor goroutine reads requests from the process
	// channel and dispatches them to core for processes.

	process := make(chan userRequest)
	go func() {
		for {
			req := <-process
			if f, ok := functions[req.rt]; ok {
				r, err := f(req.in)
				if err == nil {
					req.resp <- r
				} else {
					log.Printf("Error handling %s: %s\n", req.rt, err)
				}
			} else {
				log.Printf("Unknown user request received: %s\n", req.rt)
			}

			// Note that if an error occurs no message is sent down
			// the channel and then channel is closed. The
			// queueRequest function will see this as indication of an
			// error.

			close(req.resp)
		}
	}()

	s, l, err := NewServer(process, *staticPath, *addr, *certPath, *keyPath, *caPath)
	if err == nil {
		s.Serve(*l)
	} else {
		log.Fatalf("Error starting redoctober server: %s\n", err)
	}
}
