FROM golang:1.6-onbuild

RUN ./script/generatecert
EXPOSE 8080

CMD app \
  -addr=0.0.0.0:8080 \
  -vaultpath=diskrecord.json \
  -certs=cert/server.crt \
  -keys=cert/server.pem
