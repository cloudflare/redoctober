Red October
===========

Red October is a software-based
[two-man rule](https://en.wikipedia.org/wiki/Two-man_rule) style
encryption and decryption server.

## Building

[![Build Status](https://travis-ci.org/cloudflare/redoctober.png?branch=master)](https://travis-ci.org/cloudflare/redoctober)[![Coverage Status](http://codecov.io/github/cloudflare/redoctober/coverage.svg?branch=master)](http://codecov.io/github/cloudflare/redoctober?branch=master)

This project requires [Go 1.4](http://golang.org/doc/install#download)
or later to compile. Verify your go version by running `go version`:

    $ go version
    go version go1.4

As with any Go program you do need to set the
[GOPATH environment variable](http://golang.org/doc/code.html#GOPATH)
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
                       -certs=cert/server.crt \
                       -keys=cert/server.pem

## Quick start: example webapp

At this point Red October should be serving an example webapp. Access it using your browser:

  - [`https://localhost:8080/`](https://localhost:8080/)

## Using the API

The server exposes several JSON API endpoints. JSON of the prescribed
format is POSTed and JSON is returned.

| Path | Summary |
| ---- | ------- |
| [`/create`](#create) | Create the first admin account |
| [`/create-user`](#create-user) | Create a user |
| [`/summary`](#summary) | Display summary of the delegated keys and Red October users |
| [`/delegate`](#delegate) | Delegate a key to Red October |
| [`/purge`](#purge) | Delete all delegated keys |
| [`/password`](#password) | Change password for the authenticating user |
| [`/encrypt`](#encrypt) | Encrypt provided data with specified owners and predicates |
| [`/re-encrypt`](#re-encrypt) | Change encryption parameters of already encrypted data (delegation requirements must be met) |
| [`/decrypt`](#decrypt) | Decrypt provided data assuming necesary delegation requirements have been met |
| [`/ssh-sign-with`](#ssh-sign-with) | Sign data as an SSH oracle without disclosing the SSH private key (delegation requirements must be met) |
| [`/owners`](#owners) | List owners (those who can delegate to allow decryption) of a provided encrypted secret |
| [`/modify`](#modify) | Modify an existing user (`delete`, set `admin` flag, `revoke` admin flag) |
| [`/export`](#export) | Exports the internal vault contained encrypted user private keys, hashed passwords, public keys and other RO internal data |
| [`/order`](#order) | Adds an `Order` request to delegate credentials with specific parameters requested |
| [`/orderout`](#orders-outstanding) | Returns a list of `Order` structures for all outstanding orders |
| [`/orderinfo`](#order-information) | Returns the `Order` structure for a specified `OrderNum` |
| [`/ordercancel`](#order-cancel) | Cancel the `Order` with the specified `OrderNum` |
| [`/restore`](#restore) | Restore delegations from a persisted state (if configured). Operates like a `/delegate` call |
| [`/reset-persisted`](#reset-persisted) | Deletes all delegations from the persisted state (if configured) |
| [`/status`](#status) | Returns the status of the persistent store of delegated keys (if configured) |
| [`/index`](#web-interface) | Optionally, the server can host a static HTML file |

### Create

Create is the necessary first call to a new vault. It creates an admin account.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| No                      | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password"
}
```
- `Name` must start with an alphnumeric character and then can contain any alphanumeric character, '-', or '_' after the first character (required)
- `Password` must be at least one character long (required)

#### Response:
```json
{
    "Status": "ok"
}
```
- `Status` will be `"ok"` if successful or an error string if not.

#### Assumptions:
- This API call can **only** be called on an uninitialized vault and will fail on any call after the first user is created.
- The user created with this call is an **Admin** account.
- This user will use the `passvault.DefaultRecordType`, which is RSA.

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/create \
            -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok"}

### Create User

Create User creates a new user account. 

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| No                      | No             |

#### Request:
```json
{
    "Name": "User1", 
    "Password": "User1Password!", 
    "UserType": "ECC", 
    "HipchatName": ""
}
```
- `Name` must be unique within the RedOctober vault (required)
- `Password` must be at least one character long (required)
- `UserType` can be `"RSA"` or `"ECC"` (optional, will default to `"RSA"`)
- `HipchatName` specifies the HipChat username for `Order` notifications if configured (optional)

#### Response:
```json
{
    "Status": "ok",
}
```
- `Status` will be `"ok"` if successful or an error string if not.

#### Assumptions:
- Anyone who can access the API, can register a user with this API call.

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/create-user \
           -d '{"Name":"Bill","Password":"Lizard","UserType":"ECC"}'
    {"Status":"ok"}

### Summary

Summary provides a list of the users with keys on the system, and a
list of users who have currently delegated their key to the
server.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!"
}
```
- `Name` and `Password` are used to authenticate the request (required)

#### Response:
```json
{
    "Status": "ok", 
    "State": "",
    "Live": {
        "User1": {
            "Uses": 1,
            "Labels": ["", ""],
            "Users": ["", ""],
            "Expiry": "",
            "AltNames": {
                "key1": "value1",
                "key2": "value2"
            },
            "Admin": true,
            "Type": "RSA"
        },
        "User1-slot1": {
            "Uses": 1,
            "Labels": ["", ""],
            "Users": ["", ""],
            "Expiry": "",
            "AltNames": {
                "key1": "value1",
                "key2": "value2"
            },
            "Admin": true,
            "Type": "ECC"
        },
    },
    "All": {
        "User1": {
            "Admin": true,
            "Type": "RSA"
        }
    }
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `State` could be `active`, `inactive`, or `disabled` and is the status of the persisted keycache (delegated credentials)
- `Live` is a map of active delegations
  - The key is a combination of the username and a slot string (if provided on delegation)
  - The value is an object with details about the user and the specific delegation
- `All` is a map of users with keys in Red October
  - The key of the map is the username
  - The value is a object that says if the user is an `Admin` and if a "RSA or "ECC" key
    is used (`Type`)

#### Assumptions:
- None

#### Example query:

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


### Delegate

Delegate allows a user to delegate their decryption password to the
server for a fixed period of time and for a fixed number of
decryptions.  If the user's account is not created, it creates it.
Any new delegation overrides the previous delegation.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes*                    | No             |

*See the first assumption for this API call

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!",
    "Uses": 1,
    "Time": "1h10m5s",
    "Slot": "",
    "Users": ["User2", "User3"],
    "Labels": ["", ""]
}
```
- `Name` and `Password` are the authentication fields for this request* (required)
- `Uses` is the number of times the delegated credentials can be used for `decryption` or otherwise and must be >= 1 (required)
- `Time` is a duration the delegation is active and must parse with Go's `time.ParseDuration()` (required)
- `Slot` is a string that can be used to allow multiple delegations. This value is passed to the `keycache.Cache`, 
   which stores delegated user credentails, when a user delegates their credentials. If a user wanted to delegate multiple times with different restrictions, such as allowing one user delegated credentials for `ssh-sign-with` and another user for `decrypt`,
   then they should submit different values for `Slot` during each `/delegate` request. (optional)
- `Users` is a list of users that can use this delegation. Values must match the `Name` field used at creation of the user. (optional)
- `Labels` are strings used to match the delegation to whether a encrypted secret can be decrypted. If labels were used in 
  the encryption then at least one label must match in the delegation from both users. (optional)

*See the first assumption for this API call

#### Response:
```json
{
    "Status": "ok"
}
```
- `Status` will be `"ok"` if successful or an error string if not.


#### Assumptions:
- This API call will create a user if no user matching the `User` field is found. In that case, the same `User` and `Password` validations as `/create` and `/create-user` are followed.
- `Slot` allows for multiple delegations, but is not a validation of purpose. If two delegations are identical, but with
  different `Slot` values, either could be used assuming:
  - `Uses` has not reached `0`
  - `Time` has not expired
  - `Users` contains the user attempting to utilize the delegation
- `Labels` is for the `Order` component of RO only and is not checked when attempting to utilize a delegation

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/delegate \
           -d '{"Name":"Bill","Password":"Lizard","Time":"2h34m","Uses":3}'
    {"Status":"ok"}
    $ curl --cacert cert/server.crt https://localhost:8080/delegate \
           -d '{"Name":"Cat","Password":"Cheshire","Time":"2h34m","Uses":3}'
    {"Status":"ok"}
    $ curl --cacert cert/server.crt https://localhost:8080/delegate \
           -d '{"Name":"Dodo","Password":"Dodgson","Time":"2h34m","Uses":3}'
    {"Status":"ok"}


### Purge

Purge deletes all delegated keys in Red October.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | Yes            |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!"
}
```
- `Name` and `Password` are used to authenticate the request (required)

#### Response:
```json
{
    "Status": "ok"
}
```
- `Status` will be `"ok"` if successful or an error string if not.

#### Assumptions:
- None

#### Example input JSON format:

    $ curl --cacert cert/server.crt https://localhost:8080/purge \
           -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok"}


### Password

Password allows a user to change their password.  This password change
does not require the previously encrypted files to be re-encrypted.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!",
    "NewPassword": "User1Password!NEW",
    "HipchatName": ""
}
```
- `Name` and `Password` are used to authenticate the request (required)
- `NewPassword` will replace the current password and must be at least 1 character long (required)
- `HipchatName` is used for the internal HipChat ordering system (optional)

#### Response:
```json
{
    "Status": "ok"
}
```
- `Status` will be `"ok"` if successful or an error string if not.

#### Assumptions:
- None

### Example Input JSON format:

    $ curl --cacert cert/server.crt https://localhost:8080/password \
           -d '{"Name":"Bill","Password":"Lizard", "NewPassword": "theLizard"}'
    {"Status":"ok"}

### Encrypt

Encrypt allows a user to encrypt a piece of data. A list of valid
users is provided and a minimum number of delegated users required to
decrypt. The returned data can be decrypted as long as "Minimum"
number users from the set of "Owners" have delegated their keys to the
server.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password",
    "Minimum": 2,
    "Owners": ["User4", "User3", "Users2"],
    "LeftOwners": ["", ""],
    "RightOwners": ["", ""],
    "Predicate": "",
    "Data": "V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K",
    "Labels": ["", ""],
    "Usages": ["", ""]
}
```
- `Name` and `Password` authenticate the request (required)
- `Minimum` is the number of delegations required to decrypt. Should only be 1 or 2 unless using `LeftOwners` and `RightOwners` or 
  a `Predicate` string. (optional)
- `Owners` is a list of users that if delegated allows decryption of the secret. Need at least `Minimum` users. (required<sup>1</sup>)
- `LeftOwners` and `RightOwners` are list of users that require delegation of at least one left 
   and one right (required<sup>1</sup>)
- `Predicate` is a string that maps to an arbitrary monotone access structure. Please see [MSP Package](https://github.com/cloudflare/redoctober/tree/master/msp) (required<sup>1</sup>)
- `Data` is the base64 encoded data to be encrypted (required)
- `Labels` are strings that will mark if a decryption can occure based on matching labels in the delegation. If `Labels` is not 
  empty, then at least one value of `Labels` in the `/delegate` request must match at least one value in this request's `Labels`. (optional)
- `Usages` are strings that define how the secret can be used. Such as if it can be returned by `/decrypt` ["`decrypt`"] or used
  to with `/ssh-sign-with` [`"ssh-sign-with"`] (optional)

<sup>1</sup> Either `Owners`, `LeftOwners` and `RightOwners`, or `Predicate` is required. If one of the three is used, the other two should not be provided in the request.

#### Response:
```json
{
    "Status": "ok",
    "Response": "nWY13Rx8d7Tov0AFGu...Hok3DlNnDs8FcrU5/PrxuExq"
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` is the base64 encoded JSON object

If you base64 decode `Response`, you will get:
```json
{
    "Version":   -1,
	"Data": "c5UHBZ5KYk9K4WIf94Os/n6gtm...hu2aM1+yQO0iwhLC",
	"Signature": "Hsd88NiDaA9Ech2uHzDjLA=="
}
```
- `Version` is always -1 as it is used when HMAC-ing the encrypted data
- `Data` is a base64 encoded JSON object
- `Signature` is the HMAC signature of `Data`

If you base64 decode `Data`, you will get: 
```json
{
    "Version": 1,
    "VaultId": 12905318,
    "Labels": ["", ""],
    "Usages": ["", ""],
    "Predicate": "",
    "KeySet": [
        {
            "Name": ["User1", "User2"],
            "Key": "OnfKLlXjk0swCtdc3/GPcQ=="
        }, 
        {
            "Name": ["User2", "User3"],
            "Key": "BRJ1ZtL0IS1g6fuPAgKkGA=="
        },
        ...
    ],
    "KeySetRSA": [
        "User1": {
            "Key": "ZTXz2KehhQ+02umuhSK9pmv3q155FW6BtqDUctz1k0NOI9e9WrL+vg=="
        }, 
         "User2": {
            "Key": "R87vNqb7GhxZ8Bl+hd2osnQWVmgs68KmQ8LqoXg/3M3dvfyPBxyujw=="
        },
         "User3": {
            "Key": "uocoMcwt00sbMM2aqUhKnDdwcyWfj8AxZjUGib8pDSBYl2XfU4gM/A=="
        },
        ...
    ],
    "ShareSet": [
        "User1": ["5tJHlh2P+x9pNwOrjQsqxJMuTN9PdRqiFJ...OFYw/0="],
        "User2": ["Hg06yJnUUAjerytV6/iHr/7...bxUB/M8U7FpYDzw="],
        ...
    ],
    "IV": "xyjda++X7+8wQ0VH6Dnt/w==",
    "Data": "k9kezvCRTe6x/Fl8pVBxb...Wup5ESrQw553IxIRbY=",
    "Signature": "uUXOkuCAbGUSO4u81/ampQ=="
}
```
- `Version` is the version number of the `EncryptedData` structure
- `VaultId` will be a random 32 bit, non-negative integer identifying the vault
- `Labels` are the same as the request `Labels`
- `Usages` are the same as the request `Usages`
- `Predicate` are the same as the request `Predicate`
- `KeySet` is an array of objects with a `Name` and `Key` attribute. Each object in the array is a encrypted value using 
  intermediary keys from two users. All validate two user key delegations are stored in this array to allow decryption.
  - `Name` is an array of two users that were used to encrypt the `Data` encryption key
  - `Key` is a base64 encoded byte array that represents a doubly encrypted key, that was used to encrypt `Data`
- `KeySetRSA` is an map where the key is a user and the value is an object with one attribute `Key`. 
  - `Key` is the base64 encoded byte array that represents the intermediary key encrypted with a users RSA or ECC public key.
  Once decrypted, the intermediary key for two users can be used to decrypt the `Data` encryption key stored in the `KeySet` map.
- `ShareSet` is a map of base64 encoded byte strings representing the distributed shares generated from the requested `Predicate`
  - The map key is the user and the value is that users portion of the share
- `IV` is the AES initial vector used
- `Signature` is the internal HMAC signature of this whole structure

#### Assumptions:
- `KeySet` and `KeySetRSA` will always be populated
- `ShareSet` will only be populated when using `Predicate`

#### Example query:

    $ echo "Why is a raven like a writing desk?" | openssl base64
    V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K

    $ curl --cacert cert/server.crt https://localhost:8080/encrypt  \
            -d '{"Name":"Alice","Password":"Lewis","Minimum":2, "Owners":["Alice","Bill","Cat","Dodo"],"Data":"V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K"}'
    {"Status":"ok","Response":"eyJWZXJzaW9uIj...NSSllzPSJ9"}

Example query with a predicate:

    $ curl --cacert cert/server.crt https://localhost:8080/encrypt  \
            -d '{"Name":"Alice","Password":"Lewis","Predicate":"Alice & (Bob | Carl)",
            Data":"V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K"}'
    {"Status":"ok","Response":"eyJWZXJzaW9uIj...NSSllzPSJ9"}

The data expansion is not tied to the size of the input.


### Re-Encrypt

Re-encrypt allows for modification of encrypted data, without having to call Decrypt and then Encrypt, thus exposing the
secret to the caller. Enough delegation to Decrypt are required for this call to run. A call is very similar to except 
instead of base64 encoded data in the `Data` field, provide the `Response` value from a previous `/encrypt` call.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password",
    "Minimum": 2,
    "Owners": ["User4", "User3", "Users2", "User5"],
    "LeftOwners": ["", ""],
    "RightOwners": ["", ""],
    "Predicate": "",
    "Data": "nWY13Rx8d7Tov.../PrxuExq",
    "Labels": ["", ""],
    "Usages": ["", ""],
}
```
- `Name` and `Password` authenticate the request (required)
- `Data` is the base64 encoded response from `/encrypt` (required)
- All other fields work similar to a `/encrypt` call and will replace the original calls values

#### Response:
```json
{
    "Status": "ok",
    "Response": "QIsDoh/jp3sky...JfOTePLRAMp7k="
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` is the base64 encoded JSON object
- The internal structure of `Response` is identical to the response of an `/encrypt` call

#### Assumptions:
- Necessary delegations to decrypt the provided encrypted value should already be delegated.

#### Example query:

    $ echo "Why is a raven like a writing desk?" | openssl base64
    V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K

    $ curl --cacert cert/server.crt https://localhost:8080/re-encrypt  \
            -d '{"Name":"Alice","Password":"Lewis","Minimum":2, "Owners":["Alice","Bill","Cat","Dodo","Greg"],"Data":"eyJWZXJzaW9uIj...NSSllzPSJ9"}'
    {"Status":"ok","Response":"J6rv0zlJ7l8stG6Oz...lQu8gXKSoIR6U="}

Example query with a predicate:

    $ curl --cacert cert/server.crt https://localhost:8080/re-encrypt  \
            -d '{"Name":"Alice","Password":"Lewis","Predicate":"Alice & (Bob | Carl | Dodo)",
            Data":"eyJWZXJzaW9uIj...NSSllzPSJ9"}'
    {"Status":"ok","Response":"J6rv0zlJ7l8stG6Oz...lQu8gXKSoIR6U="}

The data expansion is not tied to the size of the input.


### Decrypt

Decrypt allows a user to decrypt a piece of data. As long as
"Minimum" number users from the set of "Owners" have delegated their
keys to the server, a base64 encoded object with the clear data and the
set of "Owners" whose private keys were used is returned.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password",
    "Data": "nWY13Rx8.../PrxuExq",
}
```
- `Name` and `Password` are used to authenticate the request (required)
- `Data` is the encrypted secret returned be a call to `/encrypt` (required)

#### Response:
```json
{
    "Data": "V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K", 
    "Secure": true,
    "Delegates": ["User2", "User3"]
}
```
- `Data` is the response from an encrypt call to be decrypted
- `Secure` this is a flag that states if the payload was properly HMAC protected
- `Delegates` notes which user's delegated keys were used to decrypt this blob

#### Assumptions:
- None

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/decrypt  \
            -d '{"Name":"Alice","Password":"Lewis","Data":"eyJWZXJzaW9uIj...NSSllzPSJ9"}'
    {"Status":"ok","Response":"eyJEYXRhI...FuMiJdfQ=="}

If there aren't enough keys delegated you'll see:

    {"Status":"need more delegated keys"}


### SSH Sign With

SSHSignWith signs a message with an SSH key previously encrypted with Red October and with a "Usages" containing `ssh-sign-with`

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!",
    "Data": "W2Y4QfAd5pf+sqFkvEzEm...p8/Zbo21YWzCNuStzyXfUcBk=",
    "TBSData": "fjELOIwcZsloJY...PPIutXm7fBLJHOJwQ8ht+8Mo="
}
```
- `Name` and `Password` are used to authenticate the request (required)
- `Data` is the encrypted SSH private key (required)
- `TBSData` is the SSH message to be signed by the SSH private key (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "rePs8L+l7xtRY50uuuFZ4As4UQZWgzfLd...q808VFaHZNJ9AIfK0vZ9c="
}
```
- `Status` will be `"ok"` if successful or an error string if not.

If you base64 decode the Response, you will get:
```json
{
    "SignatureFormat": "ssh-rsa-cert-v01@openssh.com", 
    "Signature": "M02dHSCbE/35H8RrxZmHAA==",
    "Secure": true, # boolean 
    "Delegates": ["User1", "User2"]
}
```
- `SignatureFormat` is the SSH signature type
- `Signature` is a base64 encoded byte array, which is the signature of the SSH signing operation
- `Secure` whether the HMAC validated or not
- `Delegates` are the user keys used to temporary decrypt the SSH key for signing

#### Assumptions:
- If a `Usages` value of `ssh-sign-with` was not provided, this function will not work
- If a `Usages` value of `decrypt` is not provided with `ssh-sign-with`, then the SSH key cannot be decrypted via 
  a `/decrypt` call
  - Note that while not providing `decrypt` avoids `/decrypt` returning the unencrypted SSH private key, `/re-encrypt` could
    be used to change that with the necessary delegation.

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/ssh-sign-with  \
            -d '{"Name":"Alice","Password":"Lewis","Data":"eyJWZXJzaW9uIj...NSSllzPSJ9","TBSData":"eyJEYXRhI...FuMiJdfQ=="}'
    {"Status":"ok","Response":"rePs8L+l7xtRY50uuuFZ4As4UQZWg...FaHZNJ9AIfK0vZ9c="}


### Owners

Owners allows users to determine which delegations are needed to decrypt
a piece of data.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| No                      | No             |


#### Request:
```json
{
    "Data": "V2h5IGlzIGEgcmF2ZW4gbGlrZSB...hIHdyaXRpbmcgZGVzaz8K=="
}
```
- `Data` is the response from an encrypt call to be decrypted (required)

#### Response:
```json
{
    "Status": "ok",
    "Owners": ["User1", "User2", "User3"],
    "Labels": ["", ""],
    "Predicate": ""
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Owners` will be all the users that were noted in `Owners`, `LeftOwners`, `RightOwners`, or within the `Predicate`
- `Labels` will match any that were provided in the `/encrypt` call or not be present if empty
- `Predicate` will be the value provied to `/encrypt` or not present if not used in the encryption

#### Assumptions:
- Anyone with access to an encrypted secret can look this data up in the JSON structure anyway, so it is not an authenticated request

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/owners  \
            -d '{"Data":"eyJWZXJzaW9uIj...NSSllzPSJ9"}'
    {"Status":"ok","Owners":["Alice","Bill","Cat","Dodo"]}


### Modify

Modify allows an admin user to change information about a given user.
There are 3 commands:

 - `revoke`: revokes the admin status of a user
 - `admin`: grants admin status to a user
 - `delete`: removes the account of a user

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | Yes            |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!",
    "ToModify": "User2",
    "Command": "admin"
}
```
- `Name` and `Password` are used to authenticate the request (required)
- `ToModify` username to apply the `Command` against (required)
- `Command` can be `revoke`, `admin`, `delete` (required)

#### Response:
```json
{
    "Status": "ok"
}
```
- `Status` will be `"ok"` if successful or an error string if not.

#### Assumptions:
- If a user is deleted, their key can never be delegated again because the key is deleted. If you recreate the user, 
  delegation will still fail as the keys will be different.

#### Example input JSON format:

    $ curl --cacert cert/server.crt https://localhost:8080/modify \
           -d '{"Name":"Alice","Password":"Lewis","ToModify":"Bill","Command":"admin"}'
    {"Status":"ok"}


### Export

Export Red October's internal password vault, which contains users' hashed passwords, salts, encrypted private keys and their 
public keys.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | Yes            |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!"
}
```
- `Name` and `Password` are used to authenticate the request (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "ewogICAgIlZlcnNpb24iOiAxLCAjIG51bWJlcgogI...ICAgIH0KfQo="
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` is a base64 encoded JSON object

If you were to base64 decode `Response`, you would get:
```json
{
    "Version": 1,
    "VaultId": 12905318,
    "HmacKey": "JaEu/PQTkpFjp2rML8QUbQ==",
    "Passwords": {
        "User1": {
            "Type": "",
            "PasswordSalt": "rFQLnQj+5+I6/YPOteDSNw==",
            "HashedPassword": "1WCgv8d9uXC9CcPQBQv9qw==",
            "KeySalt": "gVDCnhwOMP3obXgv0avBlQ==",
            "RSAKey": {
                "RSAExp": "jfqESm+...+nMgQM3x34wQmGswfF62MhDk2sTw==",
                "RSAExpIV": "gA0/0sS...iKNXVxXGCKXFyBlyGo4g==",
                "RSAPrimeP": "xZnZ32YvEhhOV+...boElV9EA9OJvxsyODjQ==",
                "RSAPrimePIV": "LneAiwSzMGbym7e7...nL12tcOy/LN4l8uAV8Khw==",
                "RSAPrimeQ": "s/cnhyihrUS...sfnyLuxRIb1eL3aYB18dzjn0D0g==",
                "RSAPrimeQIV": "S+8+9Q51Ig6/8in31J9y...4GD2BSig==",
                "RSAPublic": {"N":707958947...4076221507,"E":65537}
            },
            "ECKey": {
                "ECPriv":"vzrbL2pj8wxldTb6vYws7cAjIzGdh39TxepIb71GcB0=",
                "ECPrivIV": "LPXav82KMgI3pdg30VPvI2cBsk4BQLaylg45NCYR0Bc=",
                "ECPublic":{
                    "Curve":{
                        "P":11579208921035...308867097853951,
                        "N":11579208925624...259061068512369,
                        "B":41058363725114...725554835251291,
                        "Gx":4843956129391...807170824035286,
                        "Gy":3613425095677...253568414405109,
                        "BitSize":256,
                        "Name":"P-256"
                    },
                    "X":1288875298858438030...5394564151993378,
                    "Y":3728055919617037354...6025371017809918
                },
            "AltNames": {
                "": "",
                ...
            },
            "Admin": true
        },
        "User2": {
            ...
        },
        ...
    }
}
```

#### Assumptions:
- Only RSAKey or ECKey would be populated in an actual response
- While the user passwords are hashed and and the various internal values of the ECKey and RSAKey are encrypted with the
  user's cleartext password, these values are still sensitive and should be handled as such.

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/export  \
            -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok","Response":"ewogICAgIlZlcn...ICAgIH0KfQo="}

### Order

Order creates a new order and lets other users know delegations are needed.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!",
    "Duration": "1h10m5s",
    "Uses": 2,
    "Users": ["User2", "User3"],
    "EncryptedData": "nWY13Rx8d7Tov0AFGuf3IINzdHIFD.../PrxuExq",
    "Labels": ["", ""]
}
```
- `Name` and `Password` are used to authenticate the request (required)
- `Duration` must be parsable by Go's `time.ParseDuration()` and is the amount of time this `Order` is valid for (required)
- `Uses` is the number of `Uses` required of each user delegation (required)
- `Users` lists the specific user delegations being requested (required)
- `EncryptedData` is the secret that the user delegations will be used against (required)
- `Labels` are specific label requirements for the delegation requests, likely required for `/decrypt` of this specific secret (optional)

#### Response:
```json
{
    "Status": "ok",
    "Response": "ewogICJDcmVhdG9yIjogIlVz...gICAgIiIKICBdCn0K"
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` will be a base64 encoded JSON object

If you base64 decode `Response`, you will get: 
```json
{
    "Creator": "User1",
    "Users": ["User2", "User3"],
    "Num": "2ab99e07ff0405961f5e0d10",
    "TimeRequested": "2009-11-10T23:00:00Z",
    "DurationRequested": 4205000000000,
    "Delegated": 1,
    "OwnersDelegated": ["User3"],
    "Owners": ["User4", "User3", "Users2"],
    "Labels": ["", ""]
}
```
- `Creator` is the user that created the `Order`
- `Users` are the list of users in the `Order` request
- `Num` is a hex encoded random 12 byte value, which is hte `OrderId`
- `TimeRequested` is the time the `Order` was created
- `DurationRequested` is the parsed value of `Duration` in 64 bit number form
- `Delegated` is the number of user key delegations that already exist from those requested in the original request
- `OwnersDelegated` is the users that were found already delegated (this array length will be the same as `Delegated`)
- `Owners` are the users listed as `Owners` in the `EncryptedData` provided in the original request
- `Labels` are the labels included in the original request

#### Assumptions:
- Orders work with the Hipchat components of Red October, so those should be configured and user details for Hipchat registered

#### Example input JSON format:

    $ curl --cacert server/server.crt https://localhost:8080/order \
           -d '{"Name":"Alice","Password":"Lewis","Labels": ["Blue","Red"],\
           "Duration":"1h","Uses":5,"EncryptedData":"ABCDE=="}'
    {"Status": "ok","Response": "ewogICJDcmVhdG9yIjogIlVzZXIxIiwKICAiVXNlcnMiOiBbCiAgICAiVXNlcjIiLAogICAgIlVzZXIzIgogIF0sCiAgIk51bSI6ICIyYWI5OWUwN2ZmMDQwNTk2MWY1ZTBkMTAiLAogICJUaW1lUmVxdWVzdGVkIjogIjIwMDktMTEtMTBUMjM6MDA6MDBaIiwKICAiRHVyYXRpb25SZXF1ZXN0ZWQiOiA0MjA1MDAwMDAwMDAwLAogICJEZWxlZ2F0ZWQiOiAxLAogICJPd25lcnNEZWxlZ2F0ZWQiOiBbCiAgICAiVXNlcjMiCiAgXSwKICAiT3duZXJzIjogWwogICAgIlVzZXI0IiwKICAgICJVc2VyMyIsCiAgICAiVXNlcnMyIgogIF0sCiAgIkxhYmVscyI6IFsKICAgICIiLAogICAgIiIKICBdCn0K"}

### Orders Outstanding

Orders Outstanding will return a list of current order numbers

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!"
}
```
- `Name` and `Password` are used to authenticate the request (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "ewogICIyYWI5OWUwN2Z...AgIF0KICB9Cn0K"
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` will be a base64 encoded JSON object

If you base64 decode `Response`, you will get: 
```json
{
    "2ab99e07ff0405961f5e0d10": {
        "Creator": "User1",
        "Users": ["User2", "User3"],
        "Num": "2ab99e07ff0405961f5e0d10",
        "TimeRequested": "2009-11-10T23:00:00Z",
        "DurationRequested": 4205000000000,
        "Delegated": 1,
        "OwnersDelegated": ["User3"],
        "Owners": ["User4", "User3", "Users2"],
        "Labels": ["", ""]
    },
    ...
}
```
- The object is a map where the `key` is each `Order`'s `Num` (a.k.a. `OrderNum`) and the `value` is the serialized `Order` object
    - `Creator` is the user that created the `Order`
    - `Users` are the list of users in the `Order` request
    - `Num` is a hex encoded random 12 byte value, which is hte `OrderId`
    - `TimeRequested` is the time the `Order` was created
    - `DurationRequested` is the parsed value of `Duration` in 64 bit number form
    - `Delegated` is the number of user key delegations that already exist from those requested in the original request
    - `OwnersDelegated` is the users that were found already delegated (this array length will be the same as `Delegated`)
    - `Owners` are the users listed as `Owners` in the `EncryptedData` provided in the original request
    - `Labels` are the labels included in the original request

#### Assumptions:
- None

#### Example input JSON format:

    $ curl --cacert server/server.crt https://localhost:8080/orderout
           -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status": "ok","Response": "ewogICI3N2RhMWNmZDg5NjJmYjk2ODVjMTVjODQiOiB7CiAgICAiTmFtZSI6ICJBbGljZSIsCiAgICAiVXNlcnMiOiBbCiAgICAgICJCb2IiLAogICAgICAiRXZlIgogICAgXSwKICAgICJOdW0iOiAiNzdkYTFjZmQ4OTYyZmI5Njg1YzE1Yzg0IiwKICAgICJUaW1lUmVxdWVzdGVkIjogIjIwMTYtMDEtMjVUMTU6NTg6NDEuOTYxOTA2Njc5LTA4OjAwIiwKICAgICJEdXJhdGlvblJlcXVlc3RlZCI6IDM2MDAwMDAwMDAwMDAsCiAgICAiRGVsZWdhdGVkIjogMCwKICAgICJPd25lcnNEZWxlZ2F0ZWQiOiBbXSwKICAgICJPd25lcnMiOiBbCiAgICAgICJCb2IiLAogICAgICAiRXZlIgogICAgXSwKICAgICJMYWJlbHMiOiBbCiAgICAgICJCbHVlIiwKICAgICAgIlJlZCIKICAgIF0KICB9Cn0K"}

### Order Information

Returns the order information for a specific Order number.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!",
    "OrderNum": "2ab99e07ff0405961f5e0d10"
}
```
- `Name` and `Password` are used to authenticate the request (required)
- `OrderNum` is the same value returned as `Num` under and `Order` object (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "ewogICJDcmVhdG9yIjogIlVzZXIxIiwKICAiV...AogICAgIiIKICBdCn0K"
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` will be a base64 encoded JSON object

If you base64 decode `Response`, you will get: 
```json
{
    "Creator": "User1",
    "Users": ["User2", "User3"],
    "Num": "2ab99e07ff0405961f5e0d10",
    "TimeRequested": "2009-11-10T23:00:00Z",
    "DurationRequested": 4205000000000,
    "Delegated": 1,
    "OwnersDelegated": ["User3"],
    "Owners": ["User4", "User3", "Users2"],
    "Labels": ["", ""] 
}
```
- `Creator` is the user that created the `Order`
- `Users` are the list of users in the `Order` request
- `Num` is a hex encoded random 12 byte value, which is hte `OrderId`
- `TimeRequested` is the time the `Order` was created
- `DurationRequested` is the parsed value of `Duration` in 64 bit number form
- `Delegated` is the number of user key delegations that already exist from those requested in the original request
- `OwnersDelegated` is the users that were found already delegated (this array length will be the same as `Delegated`)
- `Owners` are the users listed as `Owners` in the `EncryptedData` provided in the original request
- `Labels` are the labels included in the original request

#### Assumptions:
- None

#### Example input JSON format:

    $ curl --cacert server/server.crt https://localhost:8080/orderinfo
           -d '{"Name":"Alice","Password":"Lewis", \
           "OrderNum":"77da1cfd8962fb9685c15c84"}'
    {"Status": "ok","Response": "ewogICJDcmVhdG9yIjogIlVzZXIxIiwKICAiVXNlcnMiOiBbCiAgICAiVXNlcjIiLAogICAgIlVzZXIzIgogIF0sCiAgIk51bSI6ICIyYWI5OWUwN2ZmMDQwNTk2MWY1ZTBkMTAiLAogICJUaW1lUmVxdWVzdGVkIjogIjIwMDktMTEtMTBUMjM6MDA6MDBaIiwKICAiRHVyYXRpb25SZXF1ZXN0ZWQiOiA0MjA1MDAwMDAwMDAwLAogICJEZWxlZ2F0ZWQiOiAxLAogICJPd25lcnNEZWxlZ2F0ZWQiOiBbCiAgICAiVXNlcjMiCiAgXSwKICAiT3duZXJzIjogWwogICAgIlVzZXI0IiwKICAgICJVc2VyMyIsCiAgICAiVXNlcnMyIgogIF0sCiAgIkxhYmVscyI6IFsKICAgICIiLAogICAgIiIKICBdCn0K"}


### Order Cancel

Removes a given order from Red October's Orderer.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!",
    "OrderNum": "2ab99e07ff0405961f5e0d10"
}
```
- `Name` and `Password` are used to authenticate the request (required)
- `OrderNum` is the same value returned as `Num` under and `Order` object (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "U3VjY2Vzc2Z1bGx5IHJlbW92ZWQgb3JkZXIK"
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` will be the base64 encoded string `"Successfully removed order"` if successful

#### Assumptions:
- None

#### Example input JSON format:

    $ curl --cacert server/server.crt https://localhost:8080/orderinfo
           -d '{"Name":"Alice","Password":"Lewis", \
           "OrderNum":"77da1cfd8962fb9685c15c84"}'
    {"Status":"ok","Response": "U3VjY2Vzc2Z1bGx5IHJlbW92ZWQgb3JkZXIK"}



### Restore

Restore is functionally almost identical to Delegate, but for restoring the persisted delegation cache. Once enough calls
to restore are completed to meet the delegation requirements of the persistence configuration, the current delegation cache
will be overwritten with the persisted one.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |

#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password",
    "Time": "",
}
```
- `Name` and `Password` are the authentication fields for this request* (required)
- `Time` is a duration the delegation is active and must parse with Go's `time.ParseDuration()` (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "e1N0YXR1czogYWN0aXZlfQo="
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` will be a base64 encoded JSON object if not empty

If you base64 decode `Response`, you will get: 
```json
{
    "Status": "active"
}
```
- `Status` could be `active`, `inactive`, or `disabled`

#### Assumptions:
- This function only does something if the persist module has been configured.

#### Example query:
On succesful restore

    $ curl --cacert cert/server.crt https://localhost:8080/restore  \
            -d '{"Name":"Alice","Password":"Lewis","Time":"1h10m"}'
    {"Status":"ok","Response":"e1N0YXR1czogYWN0aXZlfQo="}

Need more calls to restore to delegate more credentials

    $ curl --cacert cert/server.crt https://localhost:8080/restore  \
            -d '{"Name":"Alice","Password":"Lewis","Time":"1h10m"}'
    {"Status":"need more delegated keys","Response":""}

### Reset-Persisted

Reset-Persisted will clear the persisted delegation data if configured.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | Yes            |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!"
}
```
- `Name` and `Password` are used to authenticate the request (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "e1N0YXR1czogYWN0aXZlfQo="
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` will be a base64 encoded JSON object if not empty

If you base64 decode `Response`, you will get: 
```json
{
    "Status": "active"
}
```
- `Status` could be `active`, `inactive`, or `disabled`

#### Assumptions:
- None

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/reset-persisted  \
            -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok","Response":"e1N0YXR1czogYWN0aXZlfQo="}


### Status

Status returns the current delegation persistence state.

| Requires Authentication | Requires Admin |
| ----------------------- | -------------- |
| Yes                     | No             |


#### Request:
```json
{
    "Name": "User1",
    "Password": "User1Password!"
}
```
- `Name` and `Password` are used to authenticate the request (required)

#### Response:
```json
{
    "Status": "ok",
    "Response": "e1N0YXR1czogYWN0aXZlfQo="
}
```
- `Status` will be `"ok"` if successful or an error string if not.
- `Response` will be a base64 encoded JSON object if not empty

If you base64 decode `Response`, you will get: 
```json
{
    "Status": "active"
}
```
- `Status` could be `active`, `inactive`, or `disabled`

#### Assumptions:
- None

#### Example query:

    $ curl --cacert cert/server.crt https://localhost:8080/status  \
            -d '{"Name":"Alice","Password":"Lewis"}'
    {"Status":"ok","Response":"e1N0YXR1czogYWN0aXZlfQo="}



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


## SSH Signing Oracle

Red October can encrypt an SSH private key with a restriction that the key can
be used to sign messages, but that it should not be returned as the result of a
decrypt call. The ro client can use this feature to mimic an ssh-agent server
which authenticates a user to a remote SSH server without ever handling the
unencrypted private key directly.

Generate an ssh key **without passphrase**:

    $ ssh-keygen -f id_ed25519 -N ""

### Consign the Key to the RO Server

Encrypt with the "ssh-sign-with" usage only:

    $ ro -server localhost:443 -ca server.crt \
         -minUsers 2 -owners alice,bob -usages ssh-sign-with \
         -in id_ed25519 -out id_ed25519.encrypted encrypt

### Start the RO SSH Agent

Initiate a SSH agent with connection to the remote RO server:

    $ ro -server localhost:443 -ca server.crt ssh-agent

    2018/02/05 05:21:13 Starting Red October Secret Shell Agent
    export SSH_AUTH_SOCK=/tmp/ro_ssh_267631424/roagent.sock

### Connect to SSH via RO SSH Agent

On a separate terminal, run:

    $ export SSH_AUTH_SOCK=/tmp/ro_ssh_267631424/roagent.sock
    $ ro -in ssh_key.encrypted -pubkey ssh_key.pub ssh-add
    $ ssh-add -L # list of all public keys available through ro-ssh-agent

Now, all commands that utilize ssh-agents, such as scp, git, etc., will 
authenticate through the red october server:

    $ ssh user@hostname
    $ git -T git@github.com
    $ ...

### SSH Agent Forwarding

Moreover, since ro-ssh-agent is compatible with the ssh-agent protocol,
you can forward the ro-ssh-agent:

    localhost $ ssh -A user@middle # calls local ro-ssh-agent to ask RO server for a signature
     middle   $ ssh -A user@far    # calls local ssh-agent for a signature, which forwards the
                                   # request packet to the ro-ssh-agent
      far     $ echo Profit!
