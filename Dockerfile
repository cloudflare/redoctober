FROM golang:1.6-alpine

RUN mkdir -p /go/src/redoctober
WORKDIR /go/src/redoctober

# https://github.com/gliderlabs/docker-alpine/blob/master/docs/usage.md#disabling-cache
RUN apk --no-cache add git openssl

# build binary
COPY . /go/src/redoctober
RUN go get -d -v
RUN go install -v

# cleanup
RUN apk del git
RUN rm -rf /var/cache/apk/*

EXPOSE 8080

ENTRYPOINT ["./script/docker-start"]
CMD ["-vaultpath=diskrecord.json", "-certs=cert/server.crt", "-keys=cert/server.pem"]
