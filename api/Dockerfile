FROM golang:1.20-alpine
MAINTAINER William Durand <hello@tailordev.fr>

ARG app_env
ENV APP_ENV $app_env

ARG port=8000
ENV PORT $port

RUN apk update && \
    apk add git && \
    rm -r /var/cache/apk/*

COPY . /go/src/github.com/TailorDev/crick/api
WORKDIR /go/src/github.com/TailorDev/crick/api

CMD if [ "${APP_ENV}" == "production" ]; \
    then \
    go build && ./api; \
    else \
    go run . ; \
    fi

EXPOSE 8000
