# syntax=docker/dockerfile:1
FROM golang:1.26-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./... && go build -trimpath -ldflags="-s -w" -o /out/latency-proxy-detect .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/latency-proxy-detect /usr/local/bin/latency-proxy-detect
VOLUME /data
ENV LPD_DATA_DIR=/data
# Needs: --network host --cap-add NET_RAW --cap-add NET_ADMIN
ENTRYPOINT ["/usr/local/bin/latency-proxy-detect"]
