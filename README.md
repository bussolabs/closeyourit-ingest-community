# CloseYourIt ingest gateway

An optional buffer in front of a [CloseYourIt](https://closeyour.it) server. SDKs and agents send
their telemetry here instead of to the app; when the app is down or slow, nothing is lost: requests
wait in a NATS JetStream queue and are delivered later.

Most installations do not need it. Turn it on with `closeyourit enable ingest` on a server installed
with the CloseYourIt installer; it runs the image `ghcr.io/bussolabs/closeyourit-ingest`.

## How it works

1. A client calls the gateway with the same path, body and authentication it would use on the app.
2. The gateway forwards the request to the app (`UPSTREAM_URL`) with a 3-second timeout.
3. Normal answers, `4xx` included, go straight back to the client.
4. Network errors, `408`, `425`, `429` and `5xx` are encrypted with AES-256-GCM and stored in
   JetStream. The client gets `202` with `X-CloseYourIt-Queued: true` (the Sentry-compatible
   endpoint gets a compatible `200`).
5. The `delivery-v1` consumer retries with backoff. From the twentieth attempt, or on a permanent
   error, the message moves to a bounded dead-letter queue.

Accepted `POST` paths: `/api/v1/projects/:id/{events,metrics,logs,pageviews,replays,releases}`,
`/api/v1/projects/:id/crons/:slug/check_in`, `/api/:project_id/envelope`,
`/api/:project_id/store` and `/api/v1/servers/samples`. Everything else is refused. Bodies are
capped at 5 MiB; the default rate limit is 600 requests per minute per IP.

Control endpoints, unauthenticated: `GET /up` (process liveness), `GET /ready` (accepting traffic)
and `GET /version` (build identity).

## Configuration

| Variable | Meaning |
|---|---|
| `LISTEN_ADDRESS` | HTTP listener, for example `:8080`. |
| `UPSTREAM_URL` | Where the app answers, for example `http://closeyourit.example.com`. |
| `UPSTREAM_DIAL_ADDRESS` | Optional address to dial for the upstream host, for example `app:80`. |
| `NATS_URL`, `NATS_USER`, `NATS_PASSWORD_FILE` | The JetStream server. |
| `ENVELOPE_KEY_FILE` | 32-byte key (base64) that encrypts queued bodies. |
| `QUEUE_MAX_BYTES` | Size of the work queue; the installer uses 4 GiB. |
| `RATE_LIMIT_PER_MINUTE` | Requests per minute per IP, default 600. |
| `APP_ENV` | `production` in real installations. |
| `METRICS_LISTEN_ADDRESS` | Separate Prometheus listener, default `:9101`; keep it private. |

`nats-server.conf` and `start-nats.sh` are a reference JetStream setup; the installer ships its own.

## Development

```bash
cd gateway
go test -race ./...
go vet ./...
docker build -t closeyourit-ingest:dev .
```

## Contributing

Pull requests are welcome. This repository is a published copy: accepted changes are applied to the
upstream source and come back here with the next release. Contributors sign the CLA on their first
pull request.

## License

GNU Affero General Public License v3.0, see `LICENSE`.
