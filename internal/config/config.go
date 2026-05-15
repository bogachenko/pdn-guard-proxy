package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr     string
	TargetBaseURL  string
	NatashaBaseURL string
	RequestTimeout time.Duration
	MaxBodyBytes   int64
}

func Load() Config {
	return Config{
		ListenAddr:     envString("LISTEN_ADDR", ":8080"),
		TargetBaseURL:  envString("TARGET_BASE_URL", "http://127.0.0.1:9000"),
		NatashaBaseURL: envString("NATASHA_BASE_URL", "http://127.0.0.1:8010"),
		RequestTimeout: time.Duration(envInt("REQUEST_TIMEOUT_SECONDS", 15)) * time.Second,
		MaxBodyBytes:   int64(envInt("MAX_BODY_BYTES", 262144)),
	}
}

func envString(key string, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return parsed
}
