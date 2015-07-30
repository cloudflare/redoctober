# ro
This is a command line based Red October client. It is still under development.

## Usage
See

$ ro -h

## Example
Assume username and password is stored at RO\_USER and RO\_PASS env variables.

1. To see the current user and delegation summary:

	$ ro -server HOSTNAME:PORT summary

2. To decrypt a RO encrypted file:

	$ ro -server HOSTNAME:PORT -in FILE -out FILE decrypt
