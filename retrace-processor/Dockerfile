# Build context: services/ingest; shared isolation files are copied unchanged.
FROM python:3.14.4-alpine3.23@sha256:9e03a80a1cc6bec92c07e5eb616b295ec3c1660faa90fd08a4a4ca92e03fafde AS build
RUN apk add --no-cache openjdk21-jdk=21.0.12_p8-r0
ADD --checksum=sha256:51af0a9d41cc541d619064224aec628923bd779cbcc5a62cb914ea2d669c4063 https://dl.google.com/dl/android/maven2/com/android/tools/r8/9.4.28/r8-9.4.28.jar /app/r8.jar
COPY retrace-processor/RetraceBridge.java /app/
RUN chmod 0444 /app/r8.jar && javac -cp /app/r8.jar -d /app /app/RetraceBridge.java && cd /app && jar xf r8.jar LICENSE

FROM python:3.14.4-alpine3.23@sha256:9e03a80a1cc6bec92c07e5eb616b295ec3c1660faa90fd08a4a4ca92e03fafde
RUN apk add --no-cache openjdk21-jre-headless=21.0.12_p8-r0 libseccomp=2.6.0-r1
WORKDIR /app
COPY --from=build /app/r8.jar /app/RetraceBridge*.class /app/
COPY --from=build /app/LICENSE /usr/share/licenses/r8/LICENSE
COPY crash-processor/isolation.py /app/
COPY crash-processor/processor.py /app/base_processor.py
COPY retrace-processor/processor.py /app/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python3", "-B", "/app/processor.py"]
