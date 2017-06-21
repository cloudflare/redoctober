// Copyright (c) 2013 CloudFlare, Inc.

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/core"
	"github.com/cloudflare/redoctober/report"
	"github.com/cloudflare/redoctober/server"
	"github.com/prometheus/client_golang/prometheus"
)

// initPrometheus starts a goroutine with a Prometheus listener that
// listens on localhost:metricsPort. If the Prometheus handler can't
// be started, a log.Fatal call is made.
func initPrometheus() {
	srv := &http.Server{
		Addr:    net.JoinHostPort(cfg.Metrics.Host, cfg.Metrics.Port),
		Handler: prometheus.Handler(),
	}

	log.Printf("metrics.init start: addr=%s", srv.Addr)
	go func() {
		err := srv.ListenAndServe()
		report.Check(err, nil)
		log.Fatal(err.Error())
	}()
}

const usage = `Usage:

	redoctober -static <path> -vaultpath <path> -addr <addr> -certs <path1>[,<path2>,...] -keys <path1>[,<path2>,...] [-ca <path>]

single-cert example:
redoctober -vaultpath diskrecord.json -addr localhost:8080 -certs cert.pem -keys cert.key
multi-cert example:
redoctober -vaultpath diskrecord.json -addr localhost:8080 -certs cert1.pem,cert2.pem -keys cert1.key,cert2.key
`

var (
	cfg, cli  *config.Config
	confFile  string
	vaultPath string
)

const (
	defaultAddr        = "localhost:8080"
	defaultMetricsHost = "localhost"
	defaultMetricsPort = "8081"
)

func init() {
	// cli contains the configuration set by the command line
	// options, and cfg is the actual Red October config.
	cli = config.New()
	cfg = config.New()

	// customized the default index html with auto generated content
	server.DefaultIndexHtml = indexHtml

	cli.Server.Addr = defaultAddr
	cli.Metrics.Host = defaultMetricsHost
	cli.Metrics.Port = defaultMetricsPort

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "main usage dump\n")
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	flag.StringVar(&confFile, "f", "", "path to config file")
	flag.StringVar(&cli.Server.Addr, "addr", cli.Server.Addr,
		"Server and port separated by :")
	flag.StringVar(&cli.Server.CAPath, "ca", cli.Server.CAPath,
		"Path of TLS CA for client authentication (optional)")
	flag.StringVar(&cli.Server.CertPaths, "certs", cli.Server.CertPaths,
		"Path(s) of TLS certificate in PEM format, comma-separated")
	flag.StringVar(&cli.HipChat.Host, "hchost", cli.HipChat.Host,
		"Hipchat Url Base (ex: hipchat.com)")
	flag.StringVar(&cli.HipChat.APIKey, "hckey", cli.HipChat.APIKey,
		"Hipchat API Key")
	flag.StringVar(&cli.HipChat.Room, "hcroom", cli.HipChat.Room,
		"Hipchat Room ID")
	flag.StringVar(&cli.Server.KeyPaths, "keys", cli.Server.KeyPaths,
		"Comma-separated list of PEM-encoded TLS private keys in the same order as certs")
	flag.StringVar(&cli.Metrics.Host, "metrics-host", cli.Metrics.Host,
		"The `host` the metrics endpoint should listen on.")
	flag.StringVar(&cli.Metrics.Port, "metrics-port", cli.Metrics.Port,
		"The `port` the metrics endpoint should listen on.")
	flag.StringVar(&cli.UI.Root, "rohost", cli.UI.Root, "RedOctober URL Base (ex: localhost:8080)")
	flag.StringVar(&cli.UI.Static, "static", cli.UI.Static,
		"Path to override built-in index.html")
	flag.BoolVar(&cli.Server.Systemd, "systemdfds", cli.Server.Systemd,
		"Use systemd socket activation to listen on a file. Useful for binding privileged sockets.")
	flag.StringVar(&vaultPath, "vaultpath", "diskrecord.json", "Path to the the disk vault")

	flag.Parse()
}

//go:generate go run generate.go

func main() {
	var err error
	if confFile != "" {
		cfg, err = config.Load(confFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		cfg = cli
	}

	report.Init(cfg)

	if vaultPath == "" || !cfg.Valid() {
		if !cfg.Valid() {
			fmt.Fprintf(os.Stderr, "Invalid config.\n")
		}
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		os.Exit(2)
	}

	if err := core.Init(vaultPath, cfg); err != nil {
		report.Check(err, nil)
		log.Fatal(err)
	}

	initPrometheus()
	cpaths := strings.Split(cfg.Server.CertPaths, ",")
	kpaths := strings.Split(cfg.Server.KeyPaths, ",")
	s, l, err := server.NewServer(cfg.UI.Static, cfg.Server.Addr, cfg.Server.CAPath,
		cpaths, kpaths, cfg.Server.Systemd)
	if err != nil {
		report.Check(err, nil)
		log.Fatalf("Error starting redoctober server: %s\n", err)
	}

	log.Printf("http.serve start: addr=%s", cfg.Server.Addr)
	report.Recover(func() {
		err := s.Serve(l)
		report.Check(err, nil)
		log.Fatal(err.Error())
	})
}
