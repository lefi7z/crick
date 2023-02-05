FROM golang:1.20-alpine
MAINTAINER William Durand <hello@tailordev.fr>

RUN apk update && \
    apk add git && \
    rm -r /var/cache/apk/*

# db migration tool
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
#RUN go build -tags 'postgres' -o /usr/local/bin/migrate github.com/mattes/migrate/cli
