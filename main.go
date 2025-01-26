package main

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type DomainConfig struct {
	Domain     string `yaml:"domain"`
	RecordType string `yaml:"record_type"`
}

type Config struct {
	Domains   []DomainConfig `yaml:"domains"`
	DNSServer string         `yaml:"dns_server"`
}

var (
	listenAddr  string
	configFile  string
	dnsTimeout  time.Duration
	workerLimit int
)

var logger = logrus.New()

var (
	dnsQueryTime = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dnsexp_dns_query_time_seconds",
		Help: "DNS query time in seconds.",
	}, []string{"domain", "record_type"})

	dnsQuerySuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dnsexp_dns_query_success",
		Help: "Was this DNS query successful or not, 1 for success or 0 for failure.",
	}, []string{"domain", "record_type"})

	dnsLastCheck = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dnsexp_dns_last_check_timestamp",
		Help: "Timestamp of the last DNS query attempt.",
	}, []string{"domain", "record_type"})
)

func registerMetrics() {
	prometheus.MustRegister(dnsQueryTime)
	prometheus.MustRegister(dnsQuerySuccess)
	prometheus.MustRegister(dnsLastCheck)
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

func queryDNS(domain, recordType, dnsServer string) {
	logger.Infof("Using DNS server: %s", dnsServer)

	client := new(dns.Client)

	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.StringToType[recordType])
	msg.SetEdns0(4096, false)

	start := time.Now()

	response, _, err := client.ExchangeContext(ctx, msg, dnsServer)
	duration := time.Since(start).Seconds()

	dnsLastCheck.WithLabelValues(domain, recordType).Set(float64(time.Now().Unix()))

	if err != nil {
		logger.Errorf("DNS query failed for %s (%s): %v", domain, recordType, err)
		dnsQuerySuccess.WithLabelValues(domain, recordType).Set(0)
		dnsQueryTime.WithLabelValues(domain, recordType).Set(0)
		return
	}

	switch response.Rcode {
	case dns.RcodeSuccess:
		dnsQuerySuccess.WithLabelValues(domain, recordType).Set(1)
		dnsQueryTime.WithLabelValues(domain, recordType).Set(duration)
		logger.Infof("Query successful for %s (%s)", domain, recordType)
	case dns.RcodeNameError:
		logger.Warnf("DNS query failed for %s (%s): NXDOMAIN (domain does not exist)", domain, recordType)
		dnsQuerySuccess.WithLabelValues(domain, recordType).Set(0)
		dnsQueryTime.WithLabelValues(domain, recordType).Set(0)
	case dns.RcodeServerFailure:
		logger.Warnf("DNS query failed for %s (%s): SERVFAIL (server failure)", domain, recordType)
		dnsQuerySuccess.WithLabelValues(domain, recordType).Set(0)
		dnsQueryTime.WithLabelValues(domain, recordType).Set(0)
	case dns.RcodeRefused:
		logger.Warnf("DNS query failed for %s (%s): REFUSED (query refused by server)", domain, recordType)
		dnsQuerySuccess.WithLabelValues(domain, recordType).Set(0)
		dnsQueryTime.WithLabelValues(domain, recordType).Set(0)
	default:
		logger.Warnf("DNS query failed for %s (%s): Unknown response code %d", domain, recordType, response.Rcode)
		dnsQuerySuccess.WithLabelValues(domain, recordType).Set(0)
		dnsQueryTime.WithLabelValues(domain, recordType).Set(0)
	}
}

func workerPool(config *Config) {
	var wg sync.WaitGroup
	jobs := make(chan DomainConfig, len(config.Domains))

	for i := 0; i < workerLimit; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domainConfig := range jobs {
				queryDNS(domainConfig.Domain, domainConfig.RecordType, config.DNSServer)
			}
		}()
	}

	for _, domainConfig := range config.Domains {
		jobs <- domainConfig
	}
	close(jobs)
	wg.Wait()
}

func metricsHandler(config *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		workerPool(config)
		promhttp.Handler().ServeHTTP(w, r)
	})
}

func startExporter(cmd *cobra.Command, args []string) {
	config, err := loadConfig(configFile)
	if err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}
	if len(config.Domains) == 0 {
		logger.Warn("No domains configured")
	}
	registerMetrics()

	http.Handle("/metrics", metricsHandler(config))
	logger.Infof("Starting DNS Exporter on %s with timeout %v", listenAddr, dnsTimeout)
	logger.Fatal(http.ListenAndServe(listenAddr, nil))
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "dnsexporter",
		Short: "DNS Exporter for Prometheus",
		Run:   startExporter,
	}

	rootCmd.Flags().StringVarP(&listenAddr, "listen", "l", ":8080", "Address to listen on")
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "domains.yaml", "Path to YAML config file")
	rootCmd.Flags().DurationVarP(&dnsTimeout, "timeout", "t", 900*time.Millisecond, "DNS query timeout (e.g., 500ms, 2s)")
	rootCmd.Flags().IntVarP(&workerLimit, "workers", "w", 5, "Number of concurrent workers")

	if err := rootCmd.Execute(); err != nil {
		logger.Error(err)
		os.Exit(1)
	}
}
