FROM golang:1.26-alpine AS build
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

COPY go.mod ./
RUN go mod download

COPY . .
RUN set -eux; \
    export CGO_ENABLED=0; \
    export GOOS=${TARGETOS:-linux}; \
    if [ -n "${TARGETARCH:-}" ]; then export GOARCH="${TARGETARCH}"; fi; \
    go build -trimpath -ldflags='-s -w' -o /out/goup ./cmd/goup; \
    go build -trimpath -ldflags='-s -w' -o /out/remote-node ./cmd/remote-node

FROM alpine:3.20
RUN apk add --no-cache ca-certificates libcap-utils \
    && addgroup -S goup \
    && adduser -S -G goup goup \
    && mkdir -p /data \
    && chown -R goup:goup /data
WORKDIR /app
COPY --from=build /out/goup /usr/local/bin/goup
COPY --from=build /out/remote-node /usr/local/bin/remote-node
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN setcap cap_net_raw=+ep /usr/local/bin/goup \
    && setcap cap_net_raw=+ep /usr/local/bin/remote-node
RUN chmod +x /usr/local/bin/entrypoint.sh
USER goup
EXPOSE 8080
VOLUME ["/data"]
ENV GOUP_ADDR=:8080 \
    GOUP_DATA_DIR=/data \
    GOUP_BASE_URL=http://localhost:8080 \
    GOUP_MODE=server \
    GOUP_AUTH_MODE=disabled
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD if [ "$GOUP_MODE" = "remote-node" ]; then pidof remote-node >/dev/null; else wget -qO- http://127.0.0.1:8080/healthz || exit 1; fi
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
