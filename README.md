redoctober
==========

## Summary

Go server for two-man rule style file encryption and decryption.
A full narrative is available at [CloudFlare](http://blog.cloudflare.com/red-october-cloudflares-open-source-implementation-of-the-two-man-rule)

## Building

This project requires Go 1.1 or later to compile.

Steps to compile:

    go get github.com/cloudflare/redoctober

## Testing

Steps to test:

    go test github.com/cloudflare/redoctober...

## Running

The Red October server is a TLS server.  It requires a local file to hold the key vault, an internet address and a certificate keypair.

Usage:

    redoctober -addr=localhost:8080 \
        -vaultpath=/tmp/diskrecord.json \
        -cert=certs/servercertsigned.pem \
        -key=certs/serverkey.pem \
        -static=index.html

## Using

The server exposes several JSON API endpoints via `POST` requests

- /summary  `{ name:"user", "Password":"string"}`
- /create   `{ name:"user", "Password":"string"}`
- /delegate `{ name:"user", "Password":"string", "Time":"NhNm", "Uses":"N" }`
- /password `{ name:"user", "Password":"string", "NewPassword":"string" }`
- /modify   `{ name:"user", "Password":"string", "Command":"[admin|revoke|delete]", "ToModify":"user" }`
- /encrypt  `{ name:"user", "Password":"string", "Owners": [], "Minimum":"N", "Data":"string" }`
- /decrypt  `{ name:"user", "Password":"string", "Data":"string" }`

Optionally, the server can host a static HTML file to serve from "/index".

### Create

Create is the necessary first call to a new Red October vault.  It creates an admin account.

Example Input JSON format:

    {"Name":"Bob","Password":"Rob"}

Example Output JSON format:

    {"Status":"ok"}

### Summary

Summary provides a list of the users with keys on the system, and a list of users who have currently delegated their key to the server. Only Admins are allowed to call summary.

Example Input JSON format:

    {"Name":"Bob","Password":"Rob"}

Example Output JSON format:


    {"Status":"ok",
     "Live":{
      "Bob":{"Admin":true,"Type":"RSA","Expiry":"2013-11-15T12:13:52.238352947-08:00","Uses":5},
      "Carol":{"Admin":false,"Type":"RSA","Expiry":"2013-11-15T14:11:15.5374364-08:00","Uses":30}
     },
     "All":{
      "Alice":{"Admin":true,"Type":"RSA"},
      "Bob":{"Admin":true,"Type":"RSA"},
      "Carol":{"Admin":false,"Type":"RSA"}
     }
    }

### Delegate

Delegate allows a user to delegate their decryption password to the server for a fixed period of time and for a fixed number of decryptions.  If the user's account is not created, it creates it.  Any new delegation overrides the previous delegation.

Example Input JSON format:

    {
       "Time" : "2h34m",
       "Password" : "Rob",
       "Uses" : 3,
       "Name" : "Bob"
    }

Example Output JSON format:

    {"Status":"ok"}

### Password

Password allows a user to change their password.  This password change does not require the previously encrypted files to be re-encrypted.

Example Input JSON format:

    {"Name":"Bob","Password":"Rob","NewPassword":"Robby"}

Example Output JSON format:

    {"Status":"ok"}

### Modify

Modify allows an admin user to change information about a given user.
There are 3 commands:
- "revoke" : revokes the admin status of a user
- "admin" : grants admin status to a user
- "delete" : removes the account of a user

Example Input JSON format:

    {
       "Command" : "admin",
       "Password" : "Rob",
       "Name" : "Bob",
       "ToModify" : "Alice"
    }


Example Output JSON format:

    {"Status":"ok"}


### Encrypt

Encrypt allows an admin to encrypt a piece of data. A list of valid users is provided and a minimum number of delegated users required to decrypt.  The returned data can be decrypted as long as "Minimum" number users from the set of "Owners" have delegated their keys to the server.

Example Input JSON format:

    {
       "Password" : "Hello",
       "Owners" : [
          "Bob",
          "Alice",
          "Carol"
       ],
       "Minimum" : 2,
       "Name" : "Alice"
       "Data" : "dGhpcyBpcyB...",
    }


Example Output JSON format:

    {
        "Status":"ok",
        "Response":"eyJWZXJzaW9uIjoxL..."
    }

The data expansion is not tied to the size of the input.


### Decrypt

Decrypt allows an admin to decrypt a piece of data. As long as "Minimum" number users from the set of "Owners" have delegated their keys to the server, the clear data will be returned.

Example Input JSON format:

    {
        "Name":"Alice",
        "Password":"Hello",
        "Data":"eyJWZXJzaW9uIjoxL..."
    }

Example Output JSON format:

    {
        "Status":"ok",
        "Result":"dGhpcyBpcyBhIH..."
    }



