# ---- build ----
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY web/ web/
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /secscan .

# ---- runtime ----
FROM alpine:3.20
RUN apk add --no-cache docker-cli ca-certificates
COPY --from=build /secscan /usr/local/bin/secscan
ENV SECSCAN_DATA=/data \
    SECSCAN_LISTEN=:8510
RUN mkdir -p /data
EXPOSE 8510
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8510/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/secscan"]
