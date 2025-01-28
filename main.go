package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
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
	logLevel    string
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

	dnsQueryCount = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dnsexp_dns_query_count",
		Help: "Total number of DNS queries.",
	}, []string{"domain", "record_type"})
)

func registerMetrics() {
	prometheus.MustRegister(dnsQueryTime)
	prometheus.MustRegister(dnsQuerySuccess)
	prometheus.MustRegister(dnsLastCheck)
	prometheus.MustRegister(dnsQueryCount)
}

func loadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return &config, nil
}

var clientPool = sync.Pool{
	New: func() interface{} {
		return new(dns.Client)
	},
}

func queryDNS(domain, recordType, dnsServer string) {
	dnsQueryCount.WithLabelValues(domain, recordType).Inc()

	if _, ok := dns.StringToType[recordType]; !ok {
		logger.Errorf("Invalid record type: %s", recordType)
		return
	}

	client := clientPool.Get().(*dns.Client)
	defer clientPool.Put(client)

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
		logger.Debugf("Query successful for %s (%s)", domain, recordType)
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
	jobs := make(chan DomainConfig, workerLimit)

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
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.Fatalf("Invalid log level: %v", err)
	}
	logger.SetLevel(level)

	config, err := loadConfig(configFile)
	if err != nil {
		logger.Fatalf("Failed to load config file: %v", err)
	}
	if len(config.Domains) == 0 {
		logger.Warn("No domains configured")
	}
	if config.DNSServer == "" {
		logger.Fatal("No DNS server specified in config")
	}
	registerMetrics()

	http.Handle("/metrics", metricsHandler(config))

	server := &http.Server{Addr: listenAddr}
	go func() {
		logger.Infof("Starting DNS Exporter on %s with timeout %v", listenAddr, dnsTimeout)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Failed to start server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		logger.Errorf("Failed to shutdown server: %v", err)
	}
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
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "v", "info", "Log level (debug, info, warn, error, fatal, panic)")

	if err := rootCmd.Execute(); err != nil {
		logger.Error(err)
		os.Exit(1)
	}
}
