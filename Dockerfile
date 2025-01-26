FROM golang:1.21.0 as builder

WORKDIR /app

COPY go.* /app
COPY main.go /app

RUN CGO_ENABLED=0 GOOS=linux go build -o ./dns-exporter --ldflags '-extldflags "-static"' .

FROM scratch as runner

WORKDIR /app

COPY --from=builder /app/dns-exporter .
EXPOSE 8080
ENTRYPOINT ["/app/dns-exporter"]
