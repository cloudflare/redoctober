// Package redoctober contains the server code for Red October.
//
// Copyright (c) 2013 CloudFlare, Inc.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/cloudflare/redoctober/core"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
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
	idxHandler := &indexHandler{staticPath}
	mux.HandleFunc("/index", idxHandler.handle)
	mux.HandleFunc("/", idxHandler.handle)

	return &srv, &lstnr, nil
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
	http.ServeContent(w, r, "index.html", time.Now(), body)
}

const usage = `Usage:

	redoctober -static <path> -vaultpath <path> -addr <addr> -cert <path> -key <path> [-ca <path>]

example:
redoctober -vaultpath diskrecord.json -addr localhost:8080 -cert cert.pem -key cert.key
`

func main() {
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	var staticPath = flag.String("static", "", "Path to override built-in index.html")
	var vaultPath = flag.String("vaultpath", "diskrecord.json", "Path to the the disk vault")
	var addr = flag.String("addr", "localhost:8080", "Server and port separated by :")
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
	if err != nil {
		log.Fatalf("Error starting redoctober server: %s\n", err)
	}
	s.Serve(*l)
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
		body{padding-top: 50px;}
		.footer{ border-top: 1px solid #ccc; margin-top: 50px; padding: 20px 0;}
	</style>
</head>
<body>
	<nav class="navbar navbar-default navbar-fixed-top" role="banner">
		<div class="container">
			<div class="navbar-header">
				<a href="/" class="navbar-brand">Red October</a>
			</div>

			<div class="collapse navbar-collapse">
				<ul class="nav navbar-nav">
					<li><a href="#create">Create</a></li>
					<li><a href="#summary">Summary</a></li>
					<li><a href="#delegate">Delegate</a></li>
					<li><a href="#change-password">Change Password</a></li>
					<li><a href="#modify-user">Modify User</a></li>
					<li><a href="#encrypt">Encrypt</a></li>
					<li><a href="#decrypt">Decrypt</a></li>
				</ul>
			</div>
		</div>
	</nav>

	<div class="container">
		<h1 class="page-header">Red October Management</h1>

		<section class="row">
			<div class="col-md-6">
				<h3 id="create">Create vault/admin</h3>
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

				<h3 id="summary">User summary</h3>

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
					<button type="submit" class="btn btn-primary">Delegate</button>
				</form>
			</div>
		</section>

		<hr />

		<section class="row">
			<div id="change-password" class="col-md-6">
				<h3>Change password</h3>

				<form id="user-change-password" class="ro-user-change-password" role="form" action="/password" method="post">
					<div class="feedback change-password-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="user-name">User name</label>
							<input type="text" name="Name" class="form-control" id="user-name" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="user-pass">Password</label>
							<input type="password" name="Password" class="form-control" id="user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group">
						<label for="user-pass">New password</label>
						<input type="password" name="NewPassword" class="form-control" id="user-pass-new" placeholder="New password" required />
					</div>
					<button type="submit" class="btn btn-primary">Change password</button>
				</form>
			</div>

			<div id="modify" class="col-md-6">
				<h3>Modify User</h3>

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
			<div id="encrypt-data" class="col-md-6">
				<h3>Encrypt data</h3>

				<form id="encrypt" class="ro-user-encrypt" role="form" action="/encrypt" method="post">
					<div class="feedback encrypt-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="encrypt-user-admin">Admin User</label>
							<input type="text" name="Name" class="form-control" id="encrypt-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="encrypt-user-pass">Admin Password</label>
							<input type="password" name="Password" class="form-control" id="encrypt-user-pass" placeholder="Password" required />
						</div>
					</div>
					<div class="form-group row">
						<div class="col-md-6">
							<label for="encrypt-minimum">Minimum number of user for access</label>
							<input type="number" name="Minimum" class="form-control" id="encrypt-minimum" placeholder="2" required />
						</div>
						<div class="col-md-6">
							<label for="encrypt-owners">Owners <small>(comma separated users)</small></label>
							<input type="text" name="Owners" class="form-control" id="encrypt-owners" placeholder="e.g., Carol, Bob" required />
						</div>
					</div>
					<div class="form-group">
						<label for="encrypt-data">Data <small>(not base64 encoded)</small></label>
						<textarea name="Data" class="form-control" id="encrypt-data" rows="5" required></textarea>
					</div>
					<button type="submit" class="btn btn-primary">Encrypt!</button>
				</form>
			</div>
			<div id="decrypt-data" class="col-md-6">
				<h3>Decrypt data</h3>

				<form id="decrypt" class="ro-user-decrypt" role="form" action="/decrypt" method="post">
					<div class="feedback decrypt-feedback"></div>

					<div class="form-group row">
						<div class="col-md-6">
							<label for="decrypt-user-admin">Admin User</label>
							<input type="text" name="Name" class="form-control" id="decrypt-user-admin" placeholder="User name" required />
						</div>
						<div class="col-md-6">
							<label for="decrypt-user-pass">Admin Password</label>
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
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: 'Created user: '+data.Name }) );
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
							li.append( $('<p />', {'class': 'list-group-item-text'}).html('Type: '+user.Type+ (user.Expiry ? '<br />Expiry: '+user.Expiry : '')) );

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

				submit( $form, {
					data : data,
					success : function(d){
						$form.find('.feedback').append( makeAlert({ type: 'success', message: 'Delegating '+data.Name }) );
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
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: 'Change password for '+data.Name }) );
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
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: 'Successfully modified '+data.ToModify }) );
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
			$('body').on('submit', '#decrypt', function(evt){
				evt.preventDefault();
				var $form = $(evt.currentTarget),
					data = serialize($form);

				submit( $form, {
					data : data,
					success : function(d){
						$form.find('.feedback').empty().append( makeAlert({ type: 'success', message: '<p>Successfully decrypted data:</p><pre>'+ window.atob(d.Response)+'</pre>' }) );
					}
				});
			});
		});
	</script>
</body>
</html>
`)
