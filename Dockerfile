FROM golang:1.6-onbuild

RUN mkdir cert
RUN chmod 700 cert
# Generate private key with password "password"
RUN openssl genrsa -aes128 -passout pass:password -out cert/server.pem 2048
# Remove password from private key
RUN openssl rsa -passin pass:password -in cert/server.pem -out cert/server.pem
# Generate CSR (make sure the common name CN field matches your server
# address. It's set to "localhost" here.)
RUN openssl req -new -key cert/server.pem -out cert/server.csr -subj '/C=US/ST=California/L=Everywhere/CN=localhost'
# Sign the CSR and create certificate
RUN openssl x509 -req -days 365 -in cert/server.csr -signkey cert/server.pem -out cert/server.crt
# Clean up
RUN rm cert/server.csr
RUN chmod 600 cert/*

EXPOSE 8080

CMD app \
  -addr=localhost:8080 \
  -vaultpath=diskrecord.json \
  -certs=cert/server.crt \
  -keys=cert/server.pem
