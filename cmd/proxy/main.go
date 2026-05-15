package main

import (
	"log"
	"net/http"

	"github.com/lumiforge/pdn-guard-proxy/internal/config"
	"github.com/lumiforge/pdn-guard-proxy/internal/pdn"
	"github.com/lumiforge/pdn-guard-proxy/internal/proxy"
)

func main() {
	cfg := config.Load()

	natasha := pdn.NewNatashaClient(cfg.NatashaBaseURL, cfg.RequestTimeout)

	handler, err := proxy.NewHandler(cfg, natasha)
	if err != nil {
		log.Fatalf("failed to create proxy handler: %v", err)
	}

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler,
		ReadTimeout:  cfg.RequestTimeout,
		WriteTimeout: cfg.RequestTimeout,
	}

	log.Printf("pii proxy listening on %s, forwarding to %s", cfg.ListenAddr, cfg.TargetBaseURL)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failed: %v", err)
	}
}
