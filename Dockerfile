FROM golang:1.6-alpine

RUN apk update
RUN apk add git

RUN mkdir -p /go/src/app
WORKDIR /go/src/app
COPY . /go/src/app

RUN go get -d -v
RUN go install -v

EXPOSE 8080

CMD ./script/docker-start
