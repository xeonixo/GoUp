FROM golang:1.26-alpine AS build
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/goup ./cmd/goup

FROM alpine:3.20
RUN apk add --no-cache ca-certificates libcap-utils \
    && addgroup -S goup \
    && adduser -S -G goup goup \
    && mkdir -p /data \
    && chown -R goup:goup /data
WORKDIR /app
COPY --from=build /out/goup /usr/local/bin/goup
RUN setcap cap_net_raw=+ep /usr/local/bin/goup
USER goup
EXPOSE 8080
VOLUME ["/data"]
ENV GOUP_ADDR=:8080 \
    GOUP_DATA_DIR=/data \
    GOUP_BASE_URL=http://localhost:8080 \
    GOUP_AUTH_MODE=disabled \
    GOUP_SESSION_KEY=change-me-32-bytes-or-more
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/goup"]
