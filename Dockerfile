FROM golang:1.7.1

RUN groupadd -r redoctober --gid=999 && useradd -r -g redoctober --uid=999 redoctober

# grab openssl for generating certs and runit for chpst
RUN apt-get update && \
    apt-get install -y openssl runit

COPY . /go/src/github.com/cloudflare/redoctober
RUN go install github.com/cloudflare/redoctober

EXPOSE 8080 8081
ENV RO_CERTS=/var/lib/redoctober/data/server.crt \
    RO_KEYS=/var/lib/redoctober/data/server.pem \
    RO_DATA=/var/lib/redoctober/data \
    RO_CERTPASSWD=password \
    RO_COMMONNAME=localhost

ENTRYPOINT ["/go/src/github.com/cloudflare/redoctober/scripts/docker-entrypoint.sh"]
CMD ["redoctober", \
    "-addr=:8080", \
    "-vaultpath=/var/lib/redoctober/data/diskrecord.json", \
    "-certs=/var/lib/redoctober/data/server.crt", \
    "-keys=/var/lib/redoctober/data/server.pem"]
