# syntax=docker/dockerfile:1.12
FROM golang:1.26.8-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GIT_SHA=unknown
ARG GIT_TAG=unknown
ARG BUILD_TIME=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/bussolabs/closeyourit-ingest-community/gateway/internal/version.SHA=${GIT_SHA} -X github.com/bussolabs/closeyourit-ingest-community/gateway/internal/version.Tag=${GIT_TAG} -X github.com/bussolabs/closeyourit-ingest-community/gateway/internal/version.BuildTime=${BUILD_TIME}" \
    -o /out/ingest ./cmd/ingest

FROM alpine:3.23.5
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 ingest \
    && adduser -S -D -H -u 10001 -G ingest -s /sbin/nologin ingest
COPY --from=build /out/ingest /usr/local/bin/ingest
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/ingest"]
