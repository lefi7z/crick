FROM golang:1.20-alpine
MAINTAINER William Durand <hello@tailordev.fr>

ARG app_env
ENV APP_ENV $app_env

ARG port=8000
ENV PORT $port

RUN apk update && \
    apk add git && \
    rm -r /var/cache/apk/*

COPY . /src
WORKDIR /src

RUN if [ "${APP_ENV}" == "production" ]; \
	then \
	go build; \
	fi

CMD if [ "${APP_ENV}" == "production" ]; \
	then \
	./api; \
	else \
	go run .; \
	fi

EXPOSE 8000
