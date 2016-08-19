#!/bin/sh
set -e

# if we are not bind mounting in certs or the user has not already generated certs
# create self-signed certs
if [ ! -d $RO_DATA ]; then
	mkdir -p $RO_DATA
	chmod 700 $RO_DATA
	chown -R redoctober:redoctober $RO_DATA

	# Generate private key with password "$RO_CERTPASSWD"
	openssl genrsa -aes128 -passout pass:$RO_CERTPASSWD -out $RO_DATA/server.pem 2048
	# Remove password from private key
	openssl rsa -passin pass:$RO_CERTPASSWD -in $RO_DATA/server.pem -out $RO_DATA/server.pem
	# Generate CSR (make sure the common name CN field matches your server
	# address. It's set to "localhost" here.)
	openssl req -new -key $RO_DATA/server.pem -out $RO_DATA/server.csr -subj "/C=US/ST=California/L=Everywhere/CN=${RO_COMMONNAME}"
	# Sign the CSR and create certificate
	openssl x509 -req -days 365 -in $RO_DATA/server.csr -signkey $RO_DATA/server.pem -out $RO_DATA/server.crt

	# Clean up
	rm $RO_DATA/server.csr
	chmod 600 $RO_DATA/*
	chown -R redoctober $RO_DATA

	echo
	echo "Generated default certificates for RedOctobeer at $RO_DATA"
	echo
fi

if [ "$1" = 'redoctober' ]; then
	exec chpst -u redoctober "$@"
fi

exec "$@"
