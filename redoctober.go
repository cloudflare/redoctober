// Package redoctober contains the server code for Red October.
//
// Copyright (c) 2013 CloudFlare, Inc.

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudflare/redoctober/core"
	"github.com/coreos/go-systemd/activation"
)

// List of URLs to register and their related functions

var functions = map[string]func([]byte) ([]byte, error){
	"/create":      core.Create,
	"/create-user": core.CreateUser,
	"/summary":     core.Summary,
	"/purge":       core.Purge,
	"/delegate":    core.Delegate,
	"/password":    core.Password,
	"/encrypt":     core.Encrypt,
	"/re-encrypt":  core.ReEncrypt,
	"/decrypt":     core.Decrypt,
	"/owners":      core.Owners,
	"/modify":      core.Modify,
	"/export":      core.Export,
	"/order":       core.Order,
	"/orderout":    core.OrdersOutstanding,
	"/orderinfo":   core.OrderInfo,
	"/ordercancel": core.OrderCancel,
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

	fn, ok := functions[requestType]
	if !ok {
		http.Error(w, "Unknown request", http.StatusInternalServerError)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := fn(body)
	if err != nil {
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
	if this.staticPath != "" {
		f, err := os.Open(this.staticPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer f.Close()
		body = f
	} else {
		body = bytes.NewReader([]byte(indexHtml))
	}

	header := w.Header()
	header.Set("Content-Type", "text/html")
	header.Set("Strict-Transport-Security", "max-age=86400; includeSubDomains; preload")
	// If the server isn't HTTPS worthy, the HSTS header won't be honored.

	http.ServeContent(w, r, "index.html", time.Now(), body)
}

const usage = `Usage:

	redoctober -static <path> -vaultpath <path> -addr <addr> -certs <path1>[,<path2>,...] -keys <path1>[,<path2>,...] [-ca <path>]

single-cert example:
redoctober -vaultpath diskrecord.json -addr localhost:8080 -certs cert.pem -keys cert.key
multi-cert example:
redoctober -vaultpath diskrecord.json -addr localhost:8080 -certs cert1.pem,cert2.pem -keys cert1.key,cert2.key
`

var (
	addr             string
	caPath           string
	certsPath        string
	hcHost           string
	hcKey            string
	hcRoom           string
	keysPath         string
	roHost           string
	staticPath       string
	useSystemdSocket bool
	vaultPath        string
)

func init() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "main usage dump\n")
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	flag.StringVar(&addr, "addr", "localhost:8080", "Server and port separated by :")
	flag.StringVar(&caPath, "ca", "", "Path of TLS CA for client authentication (optional)")
	flag.StringVar(&certsPath, "certs", "", "Path(s) of TLS certificate in PEM format, comma-separated")
	flag.StringVar(&hcHost, "hchost", "", "Hipchat Url Base (ex: hipchat.com)")
	flag.StringVar(&hcKey, "hckey", "", "Hipchat API Key")
	flag.StringVar(&hcRoom, "hcroom", "", "Hipchat Room Id")
	flag.StringVar(&keysPath, "keys", "", "Path(s) of TLS private key in PEM format, comma-separated, must me in the same order as the certs")
	flag.StringVar(&roHost, "rohost", "", "RedOctober Url Base (ex: localhost:8080)")
	flag.StringVar(&staticPath, "static", "", "Path to override built-in index.html")
	flag.BoolVar(&useSystemdSocket, "systemdfds", false, "Use systemd socket activation to listen on a file. Useful for binding privileged sockets.")
	flag.StringVar(&vaultPath, "vaultpath", "diskrecord.json", "Path to the the disk vault")

	flag.Parse()
}

//go:generate go run generate.go

func main() {
	if vaultPath == "" || certsPath == "" || keysPath == "" ||
		(addr == "" && useSystemdSocket == false) {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	certPaths := strings.Split(certsPath, ",")
	keyPaths := strings.Split(keysPath, ",")

	if err := core.Init(vaultPath, hcKey, hcRoom, hcHost, roHost); err != nil {
		log.Fatal(err)
	}

	s, l, err := NewServer(staticPath, addr, caPath, certPaths, keyPaths, useSystemdSocket)
	if err != nil {
		log.Fatalf("Error starting redoctober server: %s\n", err)
	}
	s.Serve(l)
}
