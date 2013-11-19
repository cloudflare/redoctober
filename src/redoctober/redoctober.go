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
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"redoctober/core"
)

// List of URLs to register

const (
	Create   string = "/create"
	Summary         = "/summary"
	Delegate        = "/delegate"
	Password        = "/password"
	Encrypt         = "/encrypt"
	Decrypt         = "/decrypt"
	Modify          = "/modify"
)

// The channel handling user requests

var process = make(chan userRequest)

type userRequest struct {
	rt   string
	in   []byte
	resp chan []byte
}

func init() {
	go func() {
		for {
			req := <-process
			switch {
			case req.rt == Create:
				req.resp <- core.Create(req.in)
			case req.rt == Summary:
				req.resp <- core.Summary(req.in)
			case req.rt == Delegate:
				req.resp <- core.Delegate(req.in)
			case req.rt == Password:
				req.resp <- core.Password(req.in)
			case req.rt == Encrypt:
				req.resp <- core.Encrypt(req.in)
			case req.rt == Decrypt:
				req.resp <- core.Decrypt(req.in)
			case req.rt == Modify:
				req.resp <- core.Modify(req.in)
			default:
				fmt.Printf("Unknown! %s\n", req.rt)
				req.resp <- []byte("Unknown command")
			}
		}
	}()
}

func queueRequest(requestType string, w http.ResponseWriter, r *http.Request, c *tls.ConnectionState) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}

	response := make(chan []byte, 1)
	req := userRequest{rt: requestType, in: body, resp: response}
	process <- req

	code := <-response

	w.Write(code)
}

func NewServer(addr string, certPath string, keyPath string, caPath string) (*http.Server, *net.Listener, error) {
	mux := http.NewServeMux()
	srv := http.Server{
		Addr:    addr,
		Handler: mux,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	config := tls.Config{
		Certificates:             []tls.Certificate{cert},
		Rand:                     rand.Reader,
		ClientAuth:               tls.RequestClientCert,
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true,
	}
	config.Rand = rand.Reader

	// create local cert pool if present
	if caPath != "" {
		rootPool := x509.NewCertPool()
		pemCert, err := ioutil.ReadFile(caPath)
		if err != nil {
			fmt.Println(err)
			return nil, nil, err
		}
		derCert, pemCert := pem.Decode(pemCert)
		if derCert == nil {
			return nil, nil, err
		}
		cert, err := x509.ParseCertificate(derCert.Bytes)
		if err != nil {
			fmt.Println(err)
			return nil, nil, err
		}

		rootPool.AddCert(cert)
		config.ClientCAs = rootPool
	}

	conn, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	lstnr := tls.NewListener(conn, &config)

	for _, action := range []string{Create, Summary, Delegate, Password, Encrypt, Decrypt, Modify} {
		var requestType = action
		mux.HandleFunc(requestType, func(w http.ResponseWriter, r *http.Request) {
			queueRequest(requestType, w, r, r.TLS)
		})
	}

	return &srv, &lstnr, nil
}

const usage = `Usage:

	redoctober -vaultpath <path> -addr <addr> -cert <path> -key <path> [-ca <path>]

example:
redoctober /tmp/diskrecord.json localhost:8080 cert.pem cert.key

`

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

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

	core.Init(*vaultPath)
	s, l, _ := NewServer(*addr, *certPath, *keyPath, *caPath)
	s.Serve(*l)
}
