FROM python:3.14.4-alpine3.23@sha256:9e03a80a1cc6bec92c07e5eb616b295ec3c1660faa90fd08a4a4ca92e03fafde AS unpack
ADD --checksum=sha256:bfaf97804965c87155b91765f4042440a38bb002f20a62fc4da9b6b6bcb20faf https://github.com/rust-minidump/rust-minidump/releases/download/v0.27.0/minidump-stackwalk-x86_64-unknown-linux-musl.tar.xz /tmp/walker.tar.xz
RUN tar -xJf /tmp/walker.tar.xz -C /tmp
FROM python:3.14.4-alpine3.23@sha256:9e03a80a1cc6bec92c07e5eb616b295ec3c1660faa90fd08a4a4ca92e03fafde
COPY --from=unpack /tmp/minidump-stackwalk-x86_64-unknown-linux-musl/minidump-stackwalk /usr/local/bin/minidump-stackwalk
RUN apk add --no-cache libseccomp=2.6.0-r1
COPY --from=unpack /tmp/minidump-stackwalk-x86_64-unknown-linux-musl/LICENSE /usr/share/licenses/minidump-stackwalk/LICENSE
WORKDIR /app
COPY processor.py isolation.py test_processor.py /app/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python3", "-B", "/app/processor.py"]
