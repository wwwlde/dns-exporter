# DNS Exporter for Prometheus

## Overview
DNS Exporter is a Prometheus exporter that queries DNS records and exposes metrics related to query performance and success status.

This project was created as a result of issues with **pdnsd**, which caches DNS queries on hosts. The goal was to have a lightweight exporter to directly verify its operation on each server.

## Features
- Supports querying multiple DNS records
- Configurable DNS server
- Uses `miekg/dns` library for DNS resolution
- Prometheus metrics for monitoring query time, success rate, and last check timestamp
- Configurable worker pool for parallel querying
- Graceful timeout handling for DNS requests

## Installation

### Prerequisites
- Go 1.18+
- Prometheus server

### Build
```sh
# Clone the repository
git clone https://github.com/wwwlde/dns-exporter.git
cd dns-exporter

# Build the binary
go build -o ./dns-exporter --ldflags '-extldflags "-static"' .
```

### Run
```sh
./dns-exporter --config example.yaml --listen :8080 --timeout 1s --workers 5
```

## Configuration
The exporter requires a YAML configuration file specifying the DNS queries:

```yaml
domains:
  - domain: "example.com"
    record_type: "A"
  - domain: "example.org"
    record_type: "MX"
  - domain: "google.com"
    record_type: "CNAME"
dns_server: "127.0.0.1:53"
```

## Prometheus Metrics
The exporter exposes the following metrics at `/metrics`:

| Metric | Description |
|--------|-------------|
| `dnsexp_dns_query_time_seconds` | Time taken for the DNS query (seconds) |
| `dnsexp_dns_query_success` | 1 if query was successful, 0 otherwise |
| `dnsexp_dns_last_check_timestamp` | Timestamp of the last DNS query attempt |

## Example Prometheus Configuration
Add the following job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'dns_exporter'
    static_configs:
      - targets: ['localhost:8080']
```

## License
MIT License

## Author
Denys Lemeshko - [GitHub](https://github.com/wwwlde)
