Red October
===========

Red October is a software-based
[two-man rule](https://en.wikipedia.org/wiki/Two-man_rule) style
encryption and decryption server.

## Building

[![Build Status](https://travis-ci.org/cloudflare/redoctober.png?branch=master)](https://travis-ci.org/cloudflare/redoctober) [![Build Status](https://drone.io/github.com/cloudflare/redoctober/status.png)](https://drone.io/github.com/cloudflare/redoctober/latest)[![Coverage Status](http://codecov.io/github/cloudflare/redoctober/coverage.svg?branch=master)](http://codecov.io/github/cloudflare/redoctober?branch=master)

This project requires [Go 1.2](http://golang.org/doc/install#download)
or later to compile. Verify your go version by running `go version`:

    $ go version
    go version go1.2

As with any Go program you do need to set the
[GOPATH enviroment variable](http://golang.org/doc/code.html#GOPATH)
accordingly. With Go set up you can download and compile sources:

    $ go get github.com/cloudflare/redoctober

And run the tests:

    $ go test github.com/cloudflare/redoctober...

## Running

Red October is a TLS server. It requires a local file to hold the key
vault, an internet address, and a certificate keypair.

First you need to acquire a TLS certificate. The simplest (and least
secure) way is to skip the
[Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority#Issuing_a_certificate)
verification and generate a self-signed TLS certificate. Read this
[detailed guide](http://www.akadia.com/services/ssh_test_certificate.html)
or, alternatively, follow these insecure commands:

    $ mkdir cert
    $ chmod 700 cert
    ## Generate private key with password "password"
    $ openssl genrsa -aes128 -passout pass:password -out cert/server.pem 2048
    ## Remove password from private key
    $ openssl rsa -passin pass:password -in cert/server.pem -out cert/server.pem
    ## Generate CSR (make sure the common name CN field matches your server
    ## address. It's set to "localhost" here.)
    $ openssl req -new -key cert/server.pem -out cert/server.csr -subj '/C=US/ST=California/L=Everywhere/CN=localhost'
    ## Sign the CSR and create certificate
    $ openssl x509 -req -days 365 -in cert/server.csr -signkey cert/server.pem -out cert/server.crt
    ## Clean up
    $ rm cert/server.csr
    $ chmod 600 cert/*

You're ready to run the server:

    $ ./bin/redoctober -addr=localhost:8080 \
                       -vaultpath=diskrecord.json \
                       -cert=cert/server.crt \
                       -key=cert/server.pem

## Quick start: example webapp

At this point Red October should be serving an example webapp. Access it using your browser:

  - [`https://localhost:8080/`](https://localhost:8080/)

## Using the API

The server exposes several JSON API endpoints. JSON of the prescribed
format is POSTed and JSON is returned.

 - `/create`: Create the first admin account.
 - `/delegate`: Delegate a password to Red October
 - `/modify`: Modify permissions
 - `/encrypt`: Encrypt
 - `/decrypt`: Decrypt
 - `/owners`: List owners of an encrypted secret.
 - `/summary`: Display summary of the delegates
 - `/password`: Change password
 - `/index`: Optionally, the server can host a static HTML file.

### Create

Create is the necessary first call to a new vault. It creates an
admin account.

Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/create \
            -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok"}

### Delegate

Delegate allows a user to delegate their decryption password to the
server for a fixed period of time and for a fixed number of
decryptions.  If the user's account is not created, it creates it.
Any new delegation overrides the previous delegation.

Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/delegate \
           -d '{"Name":"Bill","Password":"Lizard","Time":"2h34m","Uses":3}'
    {"Status":"ok"}
    $ curl --cacert cert/server.crt https://localhost:8080/delegate \
           -d '{"Name":"Cat","Password":"Cheshire","Time":"2h34m","Uses":3}'
    {"Status":"ok"}
    $ curl --cacert cert/server.crt https://localhost:8080/delegate \
           -d '{"Name":"Dodo","Password":"Dodgson","Time":"2h34m","Uses":3}'
    {"Status":"ok"}

### Summary

Summary provides a list of the users with keys on the system, and a
list of users who have currently delegated their key to the
server.

Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/summary  \
            -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok",
     "Live":{
      "Bill":{"Admin":false,
              "Type":"RSA",
              "Expiry":"2013-11-26T08:42:29.65501032-08:00",
              "Uses":3},
      "Cat":{"Admin":false,
             "Type":"RSA",
             "Expiry":"2013-11-26T08:42:42.016311595-08:00",
             "Uses":3},
      "Dodo":{"Admin":false,
              "Type":"RSA",
              "Expiry":"2013-11-26T08:43:06.651429104-08:00",
              "Uses":3}
     },
     "All":{
      "Alice":{"Admin":true, "Type":"RSA"},
      "Bill":{"Admin":false, "Type":"RSA"},
      "Cat":{"Admin":false, "Type":"RSA"},
      "Dodo":{"Admin":false, "Type":"RSA"}
     }
    }

### Encrypt

Encrypt allows a user to encrypt a piece of data. A list of valid
users is provided and a minimum number of delegated users required to
decrypt. The returned data can be decrypted as long as "Minimum"
number users from the set of "Owners" have delegated their keys to the
server.

Example query:

    $ echo "Why is a raven like a writing desk?" | openssl base64
    V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K

    $ curl --cacert cert/server.crt https://localhost:8080/encrypt  \
            -d '{"Name":"Alice","Password":"Lewis","Minimum":2, "Owners":["Alice","Bill","Cat","Dodo"],"Data":"V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K"}'
    {"Status":"ok","Response":"eyJWZXJzaW9uIj...NSSllzPSJ9"}

The data expansion is not tied to the size of the input.

### Decrypt

Decrypt allows a user to decrypt a piece of data. As long as
"Minimum" number users from the set of "Owners" have delegated their
keys to the server, a base64 encoded object with the clear data and the
set of "Owners" whose private keys were used is returned.

Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/decrypt  \
            -d '{"Name":"Alice","Password":"Lewis","Data":"eyJWZXJzaW9uIj...NSSllzPSJ9"}'
    {"Status":"ok","Response":"eyJEYXRhI...FuMiJdfQ=="}

If there aren't enough keys delegated you'll see:

    {"Status":"Need more delegated keys"}

### Owners

Owners allows users to determine which delegations are needed to decrypt
a piece of data.

Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/owners  \
            -d '{"Data":"eyJWZXJzaW9uIj...NSSllzPSJ9"}'
    {"Status":"ok","Owners":["Alice","Bill","Cat","Dodo"]}

### Password

Password allows a user to change their password.  This password change
does not require the previously encrypted files to be re-encrypted.

Example Input JSON format:

    $ curl --cacert cert/server.crt https://localhost:8080/password \
           -d '{"Name":"Bill","Password":"Lizard", "NewPassword": "theLizard"}'
    {"Status":"ok"}

### Modify

Modify allows an admin user to change information about a given user.
There are 3 commands:

 - `revoke`: revokes the admin status of a user
 - `admin`: grants admin status to a user
 - `delete`: removes the account of a user

Example input JSON format:

    $ curl --cacert cert/server.crt https://localhost:8080/modify \
           -d '{"Name":"Alice","Password":"Lewis","ToModify":"Bill","Command":"admin"}'
    {"Status":"ok"}

### Purge

Purge deletes all delegates for an encryption key.

Example input JSON format:

    $ curl --cacert cert/server.crt https://localhost:8080/purge \
           -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok"}

### Web interface

You can build a web interface to manage the Red October service using
the `-static` flag and providing a path to the HTML file you want to
serve.

The index.html file in this repo provides a basic example for using
all of the service's features, including encrypting and decrypting
data. Data sent to the server *needs to be base64 encoded*. The
example uses JavaScript's `btoa` and `atob` functions for string
conversion. For dealing with files directly, using the
[HTML5 File API](https://developer.mozilla.org/en-US/docs/Web/API/FileReader.readAsDataURL)
would be a good option.
