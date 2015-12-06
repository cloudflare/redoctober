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
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/redoctober/core"
	"github.com/coreos/go-systemd/activation"
)

// List of URLs to register and their related functions

var functions = map[string]func([]byte) ([]byte, error){
	"/create":        core.Create,
	"/create-user":   core.CreateUser,
	"/summary":       core.Summary,
	"/purge":         core.Purge,
	"/delegate":      core.Delegate,
	"/password":      core.Password,
	"/encrypt":       core.Encrypt,
	"/re-encrypt":    core.ReEncrypt,
	"/decrypt":       core.Decrypt,
	"/ssh-sign-with": core.SSHSignWith,
	"/owners":        core.Owners,
	"/modify":        core.Modify,
	"/export":        core.Export,
	"/order":         core.Order,
	"/orderout":      core.OrdersOutstanding,
	"/orderinfo":     core.OrderInfo,
	"/ordercancel":   core.OrderCancel,
}

type userRequest struct {
	rt   string         // The request type (which will be one of the
						// keys of the functions map above
	in   []byte         // Arbitrary input data (depends on the core.*
						// function called)
	resp chan <- []byte // Channel down which a response is sent (the
						// data sent will depend on the core.* function
						// called to handle this request)
}

// queueRequest handles a single request receive on the JSON API for
// one of the functions named in the functions map above. It reads the
// request and sends it to the goroutine started in main() below for
// processing and then waits for the response.
func queueRequest(process chan<- userRequest, requestType string, w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make(chan []byte)
	process <- userRequest{rt: requestType, in: body, resp: response}

	if resp, ok := <-response; ok {
		header := w.Header()
		header.Set("Content-Type", "application/json")
		header.Set("Strict-Transport-Security", "max-age=86400; includeSubDomains; preload")

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
func NewServer(process chan<- userRequest, staticPath, addr, caPath string, certPaths, keyPaths []string, useSystemdSocket bool) (*http.Server, net.Listener, error) {
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
			queueRequest(process, requestType, w, r)
		})
	}

	// queue up web frontend
	idxHandler := &indexHandler{staticPath}
	mux.HandleFunc("/index", idxHandler.handle)
	mux.HandleFunc("/", idxHandler.handle)

	srv := http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: config,
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
		body = bytes.NewReader(indexHtml)
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
redoctober -vaultpath diskrecord.json -addr localhost:8081 -certs cert.pem -keys cert.key
multi-cert example:
redoctober -vaultpath diskrecord.json -addr localhost:8081 -certs cert1.pem,cert2.pem -keys cert1.key,cert2.key
`

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "main usage dump\n")
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	var staticPath = flag.String("static", "", "Path to override built-in index.html")
	var vaultPath = flag.String("vaultpath", "diskrecord.json", "Path to the the disk vault")
	var addr = flag.String("addr", "localhost:8081", "Server and port separated by :")
	var useSystemdSocket = flag.Bool("systemdfds", false, "Use systemd socket activation to listen on a file. Useful for binding privileged sockets.")
	var certsPathString = flag.String("certs", "", "Path(s) of TLS certificate in PEM format, comma-separated")
	var keysPathString = flag.String("keys", "", "Path(s) of TLS private key in PEM format, comma-separated, must me in the same order as the certs")
	var caPath = flag.String("ca", "", "Path of TLS CA for client authentication (optional)")
	var hcKey = flag.String("hckey", "", "Hipchat API Key")
	var hcRoom = flag.String("hcroom", "", "Hipchat Room Id")
	var hcHost = flag.String("hchost", "", "Hipchat Url Base (ex: hipchat.com)")
	var roHost = flag.String("rohost", "", "RedOctober Url Base (ex: localhost:8081)")
	flag.Parse()

	if *vaultPath == "" || *certsPathString == "" || *keysPathString == "" || (*addr == "" && *useSystemdSocket == false) {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	certPaths := strings.Split(*certsPathString, ",")
	keyPaths := strings.Split(*keysPathString, ",")

	if err := core.Init(*vaultPath, *hcKey, *hcRoom, *hcHost, *roHost); err != nil {
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
					log.Printf("http.main failed: %s: %s", req.rt, err)
				}
			} else {
				log.Printf("http.main: request=%s function is not supported", req.rt)
			}

			// Note that if an error occurs no message is sent down
			// the channel and then channel is closed. The
			// queueRequest function will see this as indication of an
			// error.

			close(req.resp)
		}
	}()

	s, l, err := NewServer(process, *staticPath, *addr, *caPath, certPaths, keyPaths, *useSystemdSocket)
	if err != nil {
		log.Fatalf("Error starting redoctober server: %s\n", err)
	}
	s.Serve(l)
}

var indexHtml = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
	<title>Red October - Two Man Rule File Encryption &amp; Decryption</title>
	<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">

	<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.0.2/css/bootstrap.min.css" />
	<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.0.2/css/bootstrap-theme.min.css" />
	<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/2.0.3/jquery.min.js"></script>
	<script src="//netdna.bootstrapcdn.com/bootstrap/3.0.2/js/bootstrap.min.js"></script>
	<style type="text/css">
		.footer{ border-top: 1px solid #ccc; margin-top: 50px; padding: 20px 0;}
	</style>
</head>
<body>
	<nav class="navbar navbar-default" role="banner">
		<div class="container">
			<div class="navbar-header">
				<a href="/" class="navbar-brand">Red October</a>
			</div>

			<div class="collapse navbar-collapse">
				<ul class="nav navbar-nav">
					<li><a href="#delegate">Delegate</a></li>
					<li><a href="#summary">Summary</a></li>
					<li><a href="#admin">Admin</a></li>
					<li><a href="#encrypt">Encrypt</a></li>
					<li><a href="#decrypt">Decrypt</a></li>
					<li><a href="#owners">Owners</a></li>
					<li><a href="#orders">Order</a></li>
				</ul>
			</div>
		</div>
	</nav>

	<div class="container">
		<h1 class="page-header">Red October Management</h1>
		<section class="row">
			<div id="delegate" class="col-md-6">
				<h3>Delegate</h3>

				<form id="user-delegate" class="ro-user-delegate" role="form" action="/delegate" method="post">
					<div class="feedback delegate-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="delegate-user">User name</label>
							<input type="text" name="Name" class="form-control" id="delegate-user" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="delegate-user-pass">Password</label>
							<input type="password" name="Password" class="form-control" id="delegate-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="delegate-user-time">Delegation Time <small>(e.g., 2h34m)</small></label>
							<input type="text" name="Time" class="form-control" id="delegate-user-time" placeholder="1h" required />
						</div>
						<div class="col-md-6">
							<label for="delegate-uses">Uses</label>
							<input type="number" name="Uses" class="form-control" id="delegate-uses" placeholder="5" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="delegate-users">Users to allow <small>(comma separated)</small></label>
							<input type="text" name="Users" class="form-control" id="delegate-users" placeholder="e.g. Alice, Bob" />
						</div>
						<div class="col-md-6">
							<label for="delegate-labels">Labels to allow <small>(comma separated)</small></label>
							<input type="text" name="Labels" class="form-control" id="delegate-labels" placeholder="e.g. Blue, Red" />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="delegate-labels">Slot Name</label>
							<input type="text" name="Slot" class="form-control" id="delegate-slot" placeholder="Afternoon" />
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Delegate</button>
				</form>
			</div>
		</section>

		<hr />

		<section class="row">
			<div id="summary" class="col-md-6">
				<h3>User summary / delegation list</h3>

				<form id="vault-summary" class="form-inline ro-summary" role="form" action="/summary" method="post">
					<div class="feedback summary-feedback"></div>

					<div class="form-group">
						<label class="sr-only" for="admin-user-auth">User name</label>
						<input type="text" name="Name" class="form-control" id="admin-user-auth" placeholder="User name" required />
					</div>
					<div class="form-group">
						<label class="sr-only" for="admin-pass-auth">Password</label>
						<input type="password" name="Password" class="form-control" id="admin-pass-auth" placeholder="Password" required />
					</div>
					<button type="submit" class="btn btn-primary">Get Summary</button>
				</form>

				<div class="hide summary-results">
					<h4>Current Delegations</h4>
					<ul class="list-group summary-user-delegations"></ul>

					<h4>All Users</h4>
					<ul class="list-group summary-all-users"></ul>
				</div>
			</div>
		</section>

		<hr />

		<section class="row">
			<div class="col-md-6" id="admin">
				<h3>Create vault</h3>
				<form id="vault-create" class="form-inline ro-admin-create" role="form" action="/create" method="post">
					<div class="feedback admin-feedback"></div>

					<div class="form-group">
						<label class="sr-only" for="admin-create-user">User name</label>
						<input type="text" name="Name" class="form-control" id="admin-create-user" placeholder="User name" required />
					</div>
					<div class="form-group">
						<label class="sr-only" for="admin-create-pass">Password</label>
						<input type="password" name="Password" class="form-control" id="admin-create-pass" placeholder="Password" required />
					</div>
					<button type="submit" class="btn btn-primary">Create Admin</button>
				</form>

				<hr />

				<h3>Create User</h3>

				<form id="user-create" class="ro-user-create" role="form" action="/create-user" method="post">
					<div class="feedback create-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="create-user">User name</label>
							<input type="text" name="Name" class="form-control" id="create-user" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="create-user-pass">Password</label>
							<input type="password" name="Password" class="form-control" id="create-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="create-user-hipchatname">Hipchat Name</label>
							<input type="text" name="HipchatName" class="form-control" id="create-hipchatname" placeholder="HipchatName" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-12">
							<label for="create-user-type">User Type</label>
							<select name="UserType" class="form-control" id="create-user-type">
								<option value="RSA">RSA</option>
								<option value="ECC">ECC</option>
							</select>
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Create</button>
				</form>
			</div>
		</section>

		<hr />

		<section class="row">
			<div id="change-password" class="col-md-6">
				<h3>Change account</h3>

				<form id="user-change-password" class="ro-user-change-password" role="form" action="/password" method="post">
					<div class="feedback change-password-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="user-name">User name</label>
							<input type="text" name="Name" class="form-control" id="user-name" placeholder="User name" required/>
						</div>
						<div class="col-md-6">
							<label for="user-pass">Password</label>
							<input type="password" name="Password" class="form-control" id="user-pass" placeholder="Password"/ required>
						</div>
					</div>
					<div class="form-group">
						<label for="user-pass">New password. Blank for no change.</label>
						<input type="password" name="NewPassword" class="form-control" id="user-pass-new" placeholder="New Password"/>
					</div>
					<div class="form-group">
						<label for="user-email">Hipchat Name. Blank for no change.</label>
						<input type="text" name="HipchatName" class="form-control" id="user-hipchatname" placeholder="New Hipchat Name"/>
					</div>
					<button type="submit" class="btn btn-primary">Change password</button>
				</form>

				<h3>Admin Controls</h3>

				<form id="user-modify" class="ro-user-modify" role="form" action="/modify" method="post">
					<div class="feedback modify-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="modify-user-admin">Admin User</label>
							<input type="text" name="Name" class="form-control" id="modify-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="modify-user-pass">Admin Password</label>
							<input type="password" name="Password" class="form-control" id="modify-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="modify-user-user">User to modify <small>(e.g., Carol)</small></label>
							<input type="text" name="ToModify" class="form-control" id="modify-user-user" required />
						</div>
						<div class="col-md-6">
							<label for="modify-user-command">Command</label>
							<select id="modify-user-command" name="Command" class="form-control" required>
								<option value="revoke">Revoke Admin Status</option>
								<option value="admin">Make Admin</option>
								<option value="delete">Delete User</option>
							</select>
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Modify user</button>
				</form>
			</div>
		</section>
		<hr />
		<section class="row">
			<div id="encrypt" class="col-md-6">
				<h3>Encrypt data</h3>

				<form id="encrypt" class="ro-user-encrypt" role="form" action="/encrypt" method="post">
					<div class="feedback encrypt-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="encrypt-user-admin">User name</label>
							<input type="text" name="Name" class="form-control" id="encrypt-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="encrypt-user-pass">Password</label>
							<input type="password" name="Password" class="form-control" id="encrypt-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="encrypt-minimum">Minimum number of users for access</label>
							<input type="number" name="Minimum" class="form-control" id="encrypt-minimum" placeholder="2" />
						</div>
						<div class="col-md-6">
							<label for="encrypt-owners">Owners <small>(comma separated users)</small></label>
							<input type="text" name="Owners" class="form-control" id="encrypt-owners" placeholder="e.g., Carol, Bob" />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-12">
							<label for="encrypt-predicate">(OR) Predicate for decryption</label>
							<input type="text" name="Predicate" class="form-control" id="encrypt-predicate" placeholder="(Alice | Bob) & Carol" />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="encrypt-labels">Labels to use <small>(comma separated)</small></label>
							<input type="text" name="Labels" class="form-control" id="encrypt-labels" placeholder="e.g. Blue, Red" />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="encrypt-usages">Usages <small>(comma separated)</small></label>
							<input type="text" name="Usages" class="form-control" id="encrypt-usages" placeholder="e.g. ssh-sign-with, decrypt" />
						</div>
					</div>
					<div class="form-group">
						<label for="encrypt-data">Data <small>(not base64 encoded)</small></label>
						<textarea name="Data" class="form-control" id="encrypt-data" rows="5" required></textarea>
					</div>
					<button type="submit" class="btn btn-primary">Encrypt!</button>
				</form>
			</div>
		</section>
		<hr />
		<section class="row">
			<div id="decrypt" class="col-md-6">
				<h3>Decrypt data</h3>

				<form id="decrypt" class="ro-user-decrypt" role="form" action="/decrypt" method="post">
					<div class="feedback decrypt-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="decrypt-user-admin">User name</label>
							<input type="text" name="Name" class="form-control" id="decrypt-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="decrypt-user-pass">Password</label>
							<input type="password" name="Password" class="form-control" id="decrypt-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group">
						<label for="decrypt-data">Data</label>
						<textarea name="Data" class="form-control" id="decrypt-data" rows="5" required></textarea>
					</div>
					<button type="submit" class="btn btn-primary">Decrypt!</button>
				</form>
			</div>
		</section>
		<hr />
		<section class="row">
			<div id="owners" class="col-md-6">
				<h3>Get owners</h3>

				<form id="owners" class="ro-user-owners" role="form" action="/owners" method="post">
					<div class="feedback owners-feedback"></div>

					<div class="form-group">
						<label for="owners-data">Data</label>
						<textarea name="Data" class="form-control" id="owners-data" rows="5" required></textarea>
					</div>
					<button type="submit" class="btn btn-primary">Get Owners</button>
				</form>
			</div>
		</section>
		<hr />
		<section class="row">
			<div id="orders" class="col-md-6">
				<h3>Create Order</h3>

				<form id="order" class="ro-user-order" role="form" action="/order" method="post">
					<div class="feedback order-feedback"></div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="order-user-admin">User name</label>
							<input type="text" name="Name" class="form-control" id="order-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="order-user-pass">Password</label>
							<input type="password" name="Password" class="form-control" id="order-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="order-duration">Duration</label>
							<input type="text" name="Duration" class="form-control" id="order-duration" placeholder="Duration (e.g., 2h34m)" required />
						</div>
						<div class="col-md-6">
							<label for="order-uses">Uses</label>
							<input type="number" name="Uses" class="form-control" id="order-uses" placeholder="5" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="order-name-users">Users to allow <small>(comma separated)</small></label>
							<input type="text" name="Users" class="form-control" id="order-name-users" placeholder="e.g. Alice, Bob" />
						</div>
						<div class="col-md-6">
							<label for="order-label">Labels</label>
							<input type="text" name="Labels" class="form-control" id="order-user-label" placeholder="Labels" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-12">
							<label for="owners-data">Encrypted Data</label>
							<textarea name="EncryptedData" class="form-control" id="owners-data" rows="5" required></textarea>
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Create Order</button>
				</form>
			</div>
		</section>
		<hr />
		<section class="row">
			<div id="ordersinfo" class="col-md-6">
				<h3>Order Info</h3>

				<form id="orderinfo" class="ro-user-order" role="form" action="/orderinfo" method="post">
					<div style="overflow-wrap: break-word;" class="feedback orderinfo-feedback"></div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="orderinfo-user-admin">User name</label>
							<input type="text" name="Name" class="form-control" id="orderinfo-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="orderinfo-user-admin">Password</label>
							<input type="password" name="Password" class="form-control" id="orderinfo-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="orderinfo-order-num">Order Number</label>
							<input type="text" name="OrderNum" class="form-control" id="orderinfo-user-label" placeholder="Order Number" required />
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Order Info</button>
				</form>
			</div>
		</section>
		<hr />
		<section class="row">
			<div id="ordersout" class="col-md-6">
				<h3>Outstanding Orders</h3>

				<form id="orderout" class="ro-user-order" role="form" action="/orderout" method="post">
					<div style="overflow-wrap: break-word;" class="feedback ordersout-feedback"></div>
					<div class="form-group">
					<div class="form-group row">
						<div class="col-md-6">
							<label for="ordersout-user-admin">User name</label>
							<input type="text" name="Name" class="form-control" id="ordersout-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="ordersout-user-admin">Password</label>
							<input type="password" name="Password" class="form-control" id="ordersout-user-pass" placeholder="Password" required />
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Outstanding Orders</button>
				</form>
			</div>
		</section>
		<section class="row">
			<div id="orderscancel" class="col-md-6">
				<h3>Order Cancel</h3>

				<form id="ordercancel" class="ro-user-order" role="form" action="/ordercancel" method="post">
					<div style="overflow-wrap: break-word;" class="feedback ordercancel-feedback"></div>
					<div class="form-group">
						<div class="row">
							<div class="col-md-6">
								<label for="ordercancel-user-admin">User name</label>
								<input type="text" name="Name" class="form-control" id="ordercancel-user-admin" placeholder="User name" required />
							</div>
							<div class="col-md-6">
								<label for="ordercancel-user-admin">Password</label>
								<input type="password" name="Password" class="form-control" id="ordercancel-user-pass" placeholder="Password" required />
							</div>
						</div>
					</div>
					<div class="form-group">
						<div class="row">
							<div class="col-md-6">
								<label for="ordercancel-order-num">Order Number</label>
								<input type="text" name="OrderNum" class="form-control" id="ordercancel-user-label" placeholder="Order Number" required />
							</div>
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Order Cancel</button>
				</form>
			</div>
		</section>
		<section class="row">
			<div id="orderscancel" class="col-md-6">
				<h3>Create Delegation Link</h3>

				<form id="orderlink" class="ro-orderlink" role="form" action="#" method="post">
					<div style="overflow-wrap: break-word;" class="feedback orderlink-feedback"></div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="orderlink-delegator">Delegator</label>
							<input type="text" name="Name" class="form-control" id="orderlink-delegator" placeholder="User name"/>
						</div>
						<div class="col-md-6">
							<label for="orderlink-labels">Labels</label>
							<input type="text" name="labels" class="form-control" id="orderlink-labels" placeholder="Labels"/>
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="orderlink-duration">Duration</label>
							<input type="text" name="duration" class="form-control" id="orderlink-duration" placeholder="1h 5m"/>
						</div>
						<div class="col-md-6">
							<label for="orderlink-uses">Uses</label>
							<input type="text" name="uses" class="form-control" id="orderlink-uses" placeholder="5"/>
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="orderlink-ordernum">Order Number</label>
							<input type="text" name="ordernum" class="form-control" id="orderlink-ordernum" placeholder="d34db33f..."/>
						</div>
						<div class="col-md-6">
							<label for="orderlink-delegatefor">Delegate For</label>
							<input type="text" name="delegatefor" class="form-control" id="orderlink-delegatefor" placeholder="e.g. Alice, Bob"/>
						</div>
					</div>
					<button type="submit" class="btn btn-primary">Create Link</button>
					</div>
				</form>
			</div>
		</section>
		<hr />
	</div>

	<footer id="footer" class="footer">
		<p class="container">Red October. CloudFlare</p>
	</footer>

	<script>
		$(function(){
			function serialize( $form ){
				var serialized = $form.serializeArray(), data = {};
				$.each(serialized, function(idx, item){ data[item.name] = item.value; });
				return data;
			}

			function makeAlert(config){ return '<div class="alert alert-dismissable alert-'+config.type+'"><button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>'+config.message+'</div>'; }

			function submit( $form, options ){
				options || (options = {});
				$.ajax({
					url: $form.attr('action'),
					data: JSON.stringify( options.data ),
					success: function(data){
						if( data.Status !== 'ok' ){
							$form.find('.feedback').empty().append( makeAlert({type: 'danger', message: data.Status}) );
							return;
						}

						if( options.success ){
							options.success.apply(this, arguments);
						}

						$form.get(0).reset();
					},
					error: options.error || function(xhr, status, error){ $form.find('.feedback').append( makeAlert({type:'danger', message: error})); }
				});
			}

			// Ajax defaults for JSON
			$.ajaxSetup({
				method: 'POST',
				dataType : 'json',
				processData : false
			});


			// Create vault/admin
			$('body').on('submit', '#vault-create', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: 'Created user: '+htmlspecialchars(data.Name) }) );
					}
				});
			});

			// Vault summary
			$('body').on('submit', '#vault-summary', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				$('#summary .feedback').empty();

				submit($form, {
					data : data,
					success : function(data){
						// Empty out the lists
						$('.summary-user-delegations, .summary-all-users').empty();
						function buildItem(key, user, loc){
							var li = $('<li />', {'class': 'list-group-item'}).appendTo(loc);
							if( user.Uses ){ li.append( $('<span />', {'class': 'badge'}).text(user.Uses+' uses remaining') ); }
							li.append( $('<h5 />', {'class': 'list-group-item-heading'}).text(key || 'Unknown') );
							li.append( $('<p />', {'class': 'list-group-item-text'}).html('Type: '+user.Type+ (user.Expiry ? '<br />Expiry: '+user.Expiry : '')+ (user.Users ? '<br />Users: '+user.Users.join(', ') : '')+ (user.Labels ? '<br />Labels: '+user.Labels.join(', ') : '')) );

							if( user.Admin ){
								li.find('h5').append(' (admin)');
							}
						}
						function buildLiveItem(k,u){ buildItem(k,u,'.summary-user-delegations'); }
						function buildAllItem(k,u){ buildItem(k,u,'.summary-all-users'); }

						$.each(data.Live, buildLiveItem);
						$.each(data.All, buildAllItem);

						$('.summary-results').removeClass('hide');
					}
				})
			});

			// Delegate
			$('body').on('submit', '#user-delegate', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				// Force uses to an integer
				data.Uses = parseInt(data.Uses, 10);
				data.Users = data.Users.split(',');
				for(var i=0, l=data.Users.length; i<l; i++){
					data.Users[i] = data.Users[i].trim();
					if (data.Users[i] == "") { data.Users.splice(i, 1); }
				}
				data.Labels = data.Labels.split(',');
				for(var i=0, l=data.Labels.length; i<l; i++){
					data.Labels[i] = data.Labels[i].trim();
					if (data.Labels[i] == "") { data.Labels.splice(i, 1); }
				}

				submit( $form, {
					data : data,
					success : function(d){
						$form.find('.feedback').append( makeAlert({ type: 'success', message: 'Delegating '+htmlspecialchars(data.Name) }) );
					}
				});
			});

			// Create
			$('body').on('submit', '#user-create', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				// Force uses to an integer
				data.Uses = parseInt(data.Uses, 10);

				submit( $form, {
					data : data,
					success : function(d){
						$form.find('.feedback').append( makeAlert({ type: 'success', message: 'Creating '+htmlspecialchars(data.Name) }) );
					}
				});
			});

			// Change password
			$('body').on('submit', '#user-change-password', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
						var msg = "Change password for ";
						if (data.NewPassword != "" && data.HipchatName != "") {
							msg = "Change Password and Hipchat Name for ";
						} else if (data.NewPassword == "" && data.HipchatName != "") {
							msg = "Change Hipchat Name for ";
						}
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: msg+htmlspecialchars(data.Name) }) );
					}
				});
			});

			// Modify user
			$('body').on('submit', '#user-modify', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: 'Successfully modified '+htmlspecialchars(data.ToModify) }) );
					}
				});
			});

			// Encrypt data
			$('body').on('submit', '#encrypt', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				data.Minimum = parseInt(data.Minimum, 10);
				data.Owners = data.Owners.split(',');
				for(var i=0, l=data.Owners.length; i<l; i++){
					data.Owners[i] = data.Owners[i].trim();
					if (data.Owners[i] == "") { data.Owners.splice(i, 1); }
				}
				data.Labels = data.Labels.split(',');
				for(var i=0, l=data.Labels.length; i<l; i++){
					data.Labels[i] = data.Labels[i].trim();
					if (data.Labels[i] == "") { data.Labels.splice(i, 1); }
				}
				data.Usages = data.Usages.split(',');
				for(var i=0, l=data.Usages.length; i<l; i++){
					data.Usages[i] = data.Usages[i].trim();
					if (data.Usages[i] == "") { data.Usages.splice(i, 1); }
				}

				// Convert data to base64.
				data.Data = window.btoa(data.Data);

				submit( $form, {
					data : data,
					success : function(d){
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: '<p>Successfully encrypted data:</p><pre>'+d.Response+'</pre>' }) );
					}
				});
			});

			// Decrypt data
			$('body').on('submit', 'form#decrypt', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
					d = JSON.parse(window.atob(d.Response));
					$form.find('.feedback').empty().append( makeAlert({ type: (d.Secure ? 'success' : 'warning'), message: '<p>Successfully decrypted data:</p><pre>'+ window.atob(d.Data)+'</pre><p>Delegates: '+d.Delegates.sort().join(', ')+'</p>' }) );
					}
				});
			});

			// Get owners
			$('body').on('submit', 'form#owners', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
					$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: '<p>Owners: '+d.Owners.sort().join(', ')+(d.Predicate == '' ? '' : '<br />Predicate: '+d.Predicate)+'</p>' }) );
					}
				});
			});
			// Create an order
			$('body').on('submit', 'form#order', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);
					// Force uses to an integer
					data.Uses = parseInt(data.Uses, 10);
					data.Labels = data.Labels.split(',');
					for(var i=0, l=data.Labels.length; i<l; i++){
						data.Labels[i] = data.Labels[i].trim();
						if (data.Labels[i] == "") { data.Labels.splice(i, 1); }
					}
					data.Users = data.Users.split(',');
					for(var i=0, l=data.Users.length; i<l; i++){
						data.Users[i] = data.Users[i].trim();
						if (data.Users[i] == "") { data.Users.splice(i, 1); }
					}

				submit( $form, {
					data : data,
					success : function(d){
					d = JSON.parse(window.atob(d.Response));
					$form.find('.feedback').empty().append(
						makeAlert({ type: 'success', message: '<p>Order Number: '+d.Num+'</p>' }) );
					}
				});
			});
			// Get order info
			$('body').on('submit', 'form#orderinfo', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);
				submit( $form, {
					data : data,
					success : function(d){
						d = window.atob(d.Response);
						try {
							var respData = JSON.parse(d);
							var msgText = "";
							for (var jj in respData) {
								if (!jj)
									continue;
								if (!respData.hasOwnProperty(jj)) {
									continue;
								}
								if (typeof(respData[jj]) == "object") {
									msgText += "<p>"+htmlspecialchars(jj)+": "+htmlspecialchars(JSON.stringify(respData[jj]))+"</p>";
								} else {
									msgText += "<p>"+htmlspecialchars(jj)+": "+htmlspecialchars(respData[jj])+"</p>";
								}
							}
							$form.find('.feedback').empty().append(makeAlert({ type: 'success', message: msgText }));
						} catch (e) {
							makeAlert({ type: 'failure', message: '<p>Invalid JSON returned</p>' });
						}
					}
				});
			});
			// Get outstanding order info
			$('body').on('submit', 'form#orderout', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
					d = JSON.parse(window.atob(d.Response));
					ordout = "";
					for (var jj in d){
						if (!d.hasOwnProperty(jj))
							continue;
						var o = d[jj];
						ordout += o.Name + " requesting " + JSON.stringify(o.Labels) + " has " + o.Delegated + "\n";

					}
					$form.find('.feedback').empty().append(
						makeAlert({ type: 'success', message: '<p>'+ordout+'</p>' }) );
					}
				});
			});
			$('body').on('submit', 'form#ordercancel', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
					d = window.atob(d.Response);
					$form.find('.feedback').empty().append(
						makeAlert({ type: 'success', message: '<p>'+d+'</p>' }) );
					}
				});
			});
			$('body').on('submit', 'form#orderlink', function(evt){
				evt.preventDefault();
				createLink();
			});
			
			// Init from query string if possible.
			var queryParams = document.location.search;
			var queryParts = queryParams.split('&');
			for (var i=0; i<queryParts.length; i++) {
				var part = queryParts[i];
				part = part.replace("?", "");
				var partPieces = part.split("=");
				if (partPieces.length != 2) {
					continue;
				}
				var setValue = null;
				var key = partPieces[0];
				var value = partPieces[1];
				switch (key) {
					case "delegator":
						setValue = $("#delegate-user");
						break;
					case "delegatee":
						setValue = $("#delegate-users");
						break;
					case "uses":
						setValue = $("#delegate-uses");
						break;
					case "label":
						setValue = $("#delegate-labels");
						break;
					case "duration":
						setValue = $("#delegate-user-time");
						break;
					case "ordernum":
						setValue = $("#delegate-slot");
						break;
					default:
						break;
				}
				if (setValue) {
					setValue.val(decodeURIComponent(value));
				}
			}
			function createLink() {
				var delegator = decodeURIComponent(document.getElementById("orderlink-delegator").value);
				var delegatee = decodeURIComponent(document.getElementById("orderlink-delegatefor").value);
				var duration  = decodeURIComponent(document.getElementById("orderlink-duration").value);
				var orderNum  = decodeURIComponent(document.getElementById("orderlink-ordernum").value);
				var labels    = decodeURIComponent(document.getElementById("orderlink-labels").value);
				var uses      = decodeURIComponent(document.getElementById("orderlink-uses").value);

				var link = "https://" + document.location.host + "?delegator="+ delegator + "&delegatee="+ delegatee + "&label=" + labels + "&ordernum=" + orderNum + "&uses=" + uses + "&duration="+ duration;
				$('.orderlink-feedback').empty().append(makeAlert({ type: 'success', message: '<p>'+htmlspecialchars(link)+'</p>' }) );
			 }
			function htmlspecialchars(s) {
				if (!isNaN(s)) {
					return s;
				}
				s = s.replace('&', '&amp;');
				s = s.replace('<', '&lt;');
				s = s.replace('>', '&gt;');
				s = s.replace('"', '&quot;');
				s = s.replace("'", '&#x27;');
				s = s.replace('/', '&#x2F;');
				return s
			}
		});
	</script>
</body>
</html>`)
