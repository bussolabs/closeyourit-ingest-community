# Compiler-only laboratory image. It is not part of the deployed processor.
FROM python:3.14.4-alpine3.23@sha256:9e03a80a1cc6bec92c07e5eb616b295ec3c1660faa90fd08a4a4ca92e03fafde
RUN apk add --no-cache build-base=0.5-r3 clang21=21.1.2-r2 lld21=21.1.2-r1 llvm21=21.1.2-r1
ENTRYPOINT ["/bin/sh"]
