# Build context: services/ingest. Legacy processor files are reused unchanged.
FROM rust:1.99.0-alpine3.23@sha256:e8dde6f7bd5650824aeede43b4652cdaf07ee5277488f300bf5b22e867d634b8 AS build
RUN apk add --no-cache build-base=0.5-r3
WORKDIR /build
COPY native-symbol-processor/Cargo.toml native-symbol-processor/Cargo.lock ./
COPY native-symbol-processor/src ./src
RUN cargo build --locked --release && mkdir -p /licenses && \
    for crate in /usr/local/cargo/registry/src/*/*; do \
      mkdir -p "/licenses/$(basename "$crate")"; \
      (cd "$crate" && find . -type f \( -iname 'license*' -o -iname 'copying*' -o -iname 'notice*' \) | \
        while IFS= read -r notice; do \
          mkdir -p "/licenses/$(basename "$crate")/$(dirname "$notice")"; \
          cp "$notice" "/licenses/$(basename "$crate")/$notice"; \
        done); \
    done && cargo metadata --locked --format-version 1 > /licenses/dependencies.json

FROM python:3.14.4-alpine3.23@sha256:9e03a80a1cc6bec92c07e5eb616b295ec3c1660faa90fd08a4a4ca92e03fafde
RUN apk add --no-cache libseccomp=2.6.0-r1
WORKDIR /app
COPY --from=build /build/target/release/cyi-native-symbol-bridge /app/native-symbol-bridge
COPY --from=build /licenses /usr/share/licenses/native-symbol-bridge
COPY crash-processor/isolation.py /app/
COPY crash-processor/processor.py /app/base_processor.py
COPY native-symbol-processor/processor.py /app/
USER 65532:65532
EXPOSE 8080
ARG GIT_SHA=unknown
ARG GIT_TAG=unknown
ARG BUILD_TIME=unknown
ENV APP_GIT_SHA=$GIT_SHA APP_GIT_TAG=$GIT_TAG APP_BUILD_TIME=$BUILD_TIME
ENTRYPOINT ["python3", "-B", "/app/processor.py"]
