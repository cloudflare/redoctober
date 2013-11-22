redoctober
==========

## Summary

Go server for two-man rule style file encryption and decryption.

## Building

This project requires Go 1.1 or later to compile.

Steps to compile:

go get github.com/cloudflare/redoctober

## Testing

Steps to test:

go test github.com/cloudflare/redoctober...

## Running

usage:
The Red October server is a TLS server.  It requires a local file to hold the key vault, an internet address and a certificate keypair.

i.e.
redoctober -addr=localhost:8080 -vaultpath=/tmp/diskrecord.json -cert=certs/servercertsigned.pem -key=certs/serverkey.pem -static=index.html

## Using

The server exposes several JSON API endpoints.  JSON of the prescribed format is POSTed and JSON is returned.

- Create = "/create"
- Summary = "/summary"
- Delegate = "/delegate"
- Password = "/password
- Modify = "/modify"
- Encrypt = "/encrypt"
- Decrypt = "/decrypt"

Optionally, the server can host a static HTML file to serve from "/index".

### Create

Create is the necessary first call to a new red october vault.  It creates an admin account.

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

    {"Name":"Bob","Password":"Rob","Time":"2h34m","Uses":3}

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

    {"Name":"Bob","Password":"Rob","ToModify":"Alice","Command":"admin"}

Example Output JSON format:

    {"Status":"ok"}

### Encrypt

Encrypt allows an admin to encrypt a piece of data. A list of valid users is provided and a minimum number of delegated users required to decrypt.  The returned data can be decrypted as long as "Minimum" number users from the set of "Owners" have delegated their keys to the server.

Example Input JSON format:

    {"Name":"Alice","Password":"Hello","Minimum":2,"Owners":["Bob","Alice","Carol"],"Data":"dGhpcyBpcyBhIHNlY3JldCBzdHJpbmcsIHNoaGhoaGhoaC4gZG9uJ3QgdGVsbCBhbnlvbmUsIG9rPyB3aGF0ZXZlciB5b3UgZG8sIGRvbid0IHRlbGwgdGhlIGNvcHMK"}

Example Output JSON format:

    {"Status":"ok","Response":"eyJWZXJzaW9uIjoxLCJWYXVsdElkIjo2NzA0ODUyOTMyNTYwNDk3NjM0LCJLZXlTZXQiOlt7Ik5hbWUiOlsiQm9iIiwiQWxpY2UiXSwiS2V5IjoicmZoSkFrSFk5eWRlQ0ppQzU1UU1JUT09In0seyJOYW1lIjpbIkJvYiIsIkNhcm9sIl0sIktleSI6Ik8xUFRFSE8rN1MvVWtLNnVYcVk5VFE9PSJ9LHsiTmFtZSI6WyJBbGljZSIsIkJvYiJdLCJLZXkiOiJBWVdWa3JwQVJwMk9iaTQ0S3VZbnNBPT0ifSx7Ik5hbWUiOlsiQWxpY2UiLCJDYXJvbCJdLCJLZXkiOiJ4aElTZUh2dDMzNkFTNVhmeXgwd1p3PT0ifSx7Ik5hbWUiOlsiQ2Fyb2wiLCJCb2IiXSwiS2V5Ijoia21VOGZiaDVkYjI1N0VMbXNzK0FQdz09In0seyJOYW1lIjpbIkNhcm9sIiwiQWxpY2UiXSwiS2V5IjoiVFpjaXd5QXphSWFSUW5USThpQTN4dz09In1dLCJLZXlTZXRSU0EiOnsiQWxpY2UiOnsiS2V5IjoiTUVEZFphSGtsMGVWRktHa2d6c0ttRXFyQkQ4SlB4Ykdla2VDRkUxWHRnUjVxdGYvTi8xUFE1SklaeVlEdXRFYWR1SVdybHc1K2phQWo2MVBVME01VDFsd0V1VktvMVpwV3RsWHAxU05Ed0R5MHNqaEZXb2lSQ0ZTUm9ZcW5ES3V0RHluUThVejFLOXBuRVlTRllnSVJDRnJYM2VhMUh0OEVEV1NUb0dsVGhBV1MrOTB1M2F4V3ZtZ1Nyc09FRm44dXZQRjdQNlRlNjdPY0FXNEV2MmFSMk92VlJHeUNJTXc1RVIvTTVPL1JRWW5ERGowT2lwMmhRRnJhK3c0MnJaYWpJejhSR3BCdzl1RWNnNDF5ZUZHRE5QNlRYQ25QZ2hFbUdCNTBJTVhMMzRUQkNNTG9UZTZMYlRGZTJpRnFGQ1c3dGNnZkdKY2h6aSs4SmVTUFRWWEFRPT0ifSwiQm9iIjp7IktleSI6IkRzSEZBTEs3cHFQQnBMSVN6b3BXbDhjb25SS0NPRlZFaW44T1l5aGZiMFQ1MVRKSVZPd1FUL2tIS0ZwSjFzcnlMSHh5UVM3TUk3T0FpZzJ3Z2NmVmZob0drdENmOExuK2tKNUpVT3JlSDY4YmJ3cnBEK3pHNnp3aFpKc0NkbEJEQ2pKU09rajc2QmtiL0JSMUhLN3FZcUdxRTMvN25jeWNuT0tPcHp5bS9DcFVrRFphSkRMak4welR2K3RxNityN0ZHUUpUdlpqRzZLbjBzamlGREtlbnlmSVhzd0hSQ3NjbTVENU8xZXZBSXNxeE9kOGJoUmw5bXovQWNCd1BpT3A1YVlpdGJxNnZidW1VbVg0UDYzeVJBaWxaaTZnOGZvN255Nnl1REtYeE9DYzFPeUFGamZGMVloSTJrT2pEUExkTCtrQjI5dlFsblkxODltRVVvL3pRUT09In0sIkNhcm9sIjp7IktleSI6ImNQZEhGYXZ5aUF4VmpPR2x6eVF2d0lTZGhtMCtZNzFVcUpXUFNKZ1h5a3Zoekl6TzNoQmV6OHhUTkxrRldkdnQ0T0NWc2hPMTd3VDY4cnhxZUE1bzJocmVjUVBUZ2IzbHVaWFZ5MDFxaUlDZXZveUw0cTljR2hNQUVsVWZoMGZEb3MrZVo1VEpTbElESWZSZGRXbEZ1NmUxT3ZmQWxOZ3A5Z3VSRVhNR05QcGxNa2YwUlpWZ1RHNGpka0VpUVVTRDQxemJBOWwxand4UkxvYXNrRXBLeFEycVp3YnBjbGRhUUk3WUlqbzlEMk5zM2V5N29YbmQ2RXJOQXpOMzRKc1h1QXE0a3NkNlRJdTdpQktYYzlvNUV1WWNnaEpNTnRaWkljc05ueVBHVlNQY2IwdzFrYVJPWTNndTFidFZhU2FqVDN6TmtyZXpzQy9td1hBaDRmajVvdz09In19LCJJViI6InRqZWF3VWVKU0hocEwzRnFZZy9hNkE9PSIsIkRhdGEiOiJnRGxORHFiQWU5eVd0M1ZNMW1SSldDMjJVRkFvcFdSbVVyWTI5RjJQdUlLUmJaYWpJRlE1RmZsTmtzR2tRTjREVWZZc0wrelJTeHp6bUtTaXNCZVdHNUVCZDlTdXJmdktSQlQ1TEhmUHN0UzNxbEJtY2lWb21Qc1lOaUthN0ZVUGxVcUE2NHVyaTVXQUxpdWQvVExZQXc9PSIsIlNpZ25hdHVyZSI6IlB0dkxNUkpxR1FvNHlIRXVuN083d2NzV1A1az0ifQ=="}

The data expansion is not tied to the size of the input.


### Decrypt

Decrypt allows an admin to decrypt a piece of data. As long as "Minimum" number users from the set of "Owners" have delegated their keys to the server, the clear data will be returned.

Example Input JSON format:

    {"Name":"Alice","Password":"Hello","Data":"eyJWZXJzaW9uIjoxLCJWYXVsdElkIjo2NzA0ODUyOTMyNTYwNDk3NjM0LCJLZXlTZXQiOlt7Ik5hbWUiOlsiQm9iIiwiQWxpY2UiXSwiS2V5IjoicmZoSkFrSFk5eWRlQ0ppQzU1UU1JUT09In0seyJOYW1lIjpbIkJvYiIsIkNhcm9sIl0sIktleSI6Ik8xUFRFSE8rN1MvVWtLNnVYcVk5VFE9PSJ9LHsiTmFtZSI6WyJBbGljZSIsIkJvYiJdLCJLZXkiOiJBWVdWa3JwQVJwMk9iaTQ0S3VZbnNBPT0ifSx7Ik5hbWUiOlsiQWxpY2UiLCJDYXJvbCJdLCJLZXkiOiJ4aElTZUh2dDMzNkFTNVhmeXgwd1p3PT0ifSx7Ik5hbWUiOlsiQ2Fyb2wiLCJCb2IiXSwiS2V5Ijoia21VOGZiaDVkYjI1N0VMbXNzK0FQdz09In0seyJOYW1lIjpbIkNhcm9sIiwiQWxpY2UiXSwiS2V5IjoiVFpjaXd5QXphSWFSUW5USThpQTN4dz09In1dLCJLZXlTZXRSU0EiOnsiQWxpY2UiOnsiS2V5IjoiTUVEZFphSGtsMGVWRktHa2d6c0ttRXFyQkQ4SlB4Ykdla2VDRkUxWHRnUjVxdGYvTi8xUFE1SklaeVlEdXRFYWR1SVdybHc1K2phQWo2MVBVME01VDFsd0V1VktvMVpwV3RsWHAxU05Ed0R5MHNqaEZXb2lSQ0ZTUm9ZcW5ES3V0RHluUThVejFLOXBuRVlTRllnSVJDRnJYM2VhMUh0OEVEV1NUb0dsVGhBV1MrOTB1M2F4V3ZtZ1Nyc09FRm44dXZQRjdQNlRlNjdPY0FXNEV2MmFSMk92VlJHeUNJTXc1RVIvTTVPL1JRWW5ERGowT2lwMmhRRnJhK3c0MnJaYWpJejhSR3BCdzl1RWNnNDF5ZUZHRE5QNlRYQ25QZ2hFbUdCNTBJTVhMMzRUQkNNTG9UZTZMYlRGZTJpRnFGQ1c3dGNnZkdKY2h6aSs4SmVTUFRWWEFRPT0ifSwiQm9iIjp7IktleSI6IkRzSEZBTEs3cHFQQnBMSVN6b3BXbDhjb25SS0NPRlZFaW44T1l5aGZiMFQ1MVRKSVZPd1FUL2tIS0ZwSjFzcnlMSHh5UVM3TUk3T0FpZzJ3Z2NmVmZob0drdENmOExuK2tKNUpVT3JlSDY4YmJ3cnBEK3pHNnp3aFpKc0NkbEJEQ2pKU09rajc2QmtiL0JSMUhLN3FZcUdxRTMvN25jeWNuT0tPcHp5bS9DcFVrRFphSkRMak4welR2K3RxNityN0ZHUUpUdlpqRzZLbjBzamlGREtlbnlmSVhzd0hSQ3NjbTVENU8xZXZBSXNxeE9kOGJoUmw5bXovQWNCd1BpT3A1YVlpdGJxNnZidW1VbVg0UDYzeVJBaWxaaTZnOGZvN255Nnl1REtYeE9DYzFPeUFGamZGMVloSTJrT2pEUExkTCtrQjI5dlFsblkxODltRVVvL3pRUT09In0sIkNhcm9sIjp7IktleSI6ImNQZEhGYXZ5aUF4VmpPR2x6eVF2d0lTZGhtMCtZNzFVcUpXUFNKZ1h5a3Zoekl6TzNoQmV6OHhUTkxrRldkdnQ0T0NWc2hPMTd3VDY4cnhxZUE1bzJocmVjUVBUZ2IzbHVaWFZ5MDFxaUlDZXZveUw0cTljR2hNQUVsVWZoMGZEb3MrZVo1VEpTbElESWZSZGRXbEZ1NmUxT3ZmQWxOZ3A5Z3VSRVhNR05QcGxNa2YwUlpWZ1RHNGpka0VpUVVTRDQxemJBOWwxand4UkxvYXNrRXBLeFEycVp3YnBjbGRhUUk3WUlqbzlEMk5zM2V5N29YbmQ2RXJOQXpOMzRKc1h1QXE0a3NkNlRJdTdpQktYYzlvNUV1WWNnaEpNTnRaWkljc05ueVBHVlNQY2IwdzFrYVJPWTNndTFidFZhU2FqVDN6TmtyZXpzQy9td1hBaDRmajVvdz09In19LCJJViI6InRqZWF3VWVKU0hocEwzRnFZZy9hNkE9PSIsIkRhdGEiOiJnRGxORHFiQWU5eVd0M1ZNMW1SSldDMjJVRkFvcFdSbVVyWTI5RjJQdUlLUmJaYWpJRlE1RmZsTmtzR2tRTjREVWZZc0wrelJTeHp6bUtTaXNCZVdHNUVCZDlTdXJmdktSQlQ1TEhmUHN0UzNxbEJtY2lWb21Qc1lOaUthN0ZVUGxVcUE2NHVyaTVXQUxpdWQvVExZQXc9PSIsIlNpZ25hdHVyZSI6IlB0dkxNUkpxR1FvNHlIRXVuN083d2NzV1A1az0ifQ=="}

Example Output JSON format:

    {"Status":"ok","Result":"dGhpcyBpcyBhIHNlY3JldCBzdHJpbmcsIHNoaGhoaGhoaC4gZG9uJ3QgdGVsbCBhbnlvbmUsIG9rPyB3aGF0ZXZlciB5b3UgZG8sIGRvbid0IHRlbGwgdGhlIGNvcHMK"}


