FROM golang:1.6.3

COPY . /go/src/github.com/cloudflare/redoctober
RUN go get github.com/cloudflare/redoctober/...

EXPOSE 8080
ENTRYPOINT ["redoctober"]
