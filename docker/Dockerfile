# Preston-Check Docker image
#
# Build:
#   docker build -t prestoncheck/scan:latest -f docker/Dockerfile .
#
# Use:
#   docker run --rm -v $(pwd):/src prestoncheck/scan:latest --report /src/preston-check-report.md

FROM alpine:3.19

LABEL org.opencontainers.image.title="Preston-Check"
LABEL org.opencontainers.image.description="Pre-deployment security audit for fintech and financial systems"
LABEL org.opencontainers.image.source="https://github.com/preston-check/preston-check"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache \
    bash \
    grep \
    gawk \
    sed \
    findutils \
    coreutils \
    openssl \
    git \
    curl \
    pandoc

RUN adduser -D -h /home/preston -s /bin/bash preston

WORKDIR /opt/preston-check
COPY preston-check.sh /opt/preston-check/
COPY config.yml /opt/preston-check/
COPY checks/ /opt/preston-check/checks/
COPY lib/ /opt/preston-check/lib/
COPY lang/ /opt/preston-check/lang/
COPY templates/ /opt/preston-check/templates/
COPY tools/ /opt/preston-check/tools/
COPY LICENSE NOTICE TRADEMARK.md /opt/preston-check/

RUN chmod +x /opt/preston-check/preston-check.sh \
    && chmod +x /opt/preston-check/checks/*.sh \
    && chmod +x /opt/preston-check/tools/*.sh \
    && find /opt/preston-check/checks/community -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

USER preston
WORKDIR /src

ENV SOURCE_DIR=/src
ENV PRESTON_HOME=/opt/preston-check

ENTRYPOINT ["/opt/preston-check/preston-check.sh"]
CMD ["--help"]
