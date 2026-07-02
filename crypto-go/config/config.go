package config

import (
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	Port             string
	KeystorePath     string
	KeystorePassword string
}

func Load() *Config {
	_ = godotenv.Load()
	return &Config{
		Port:             getEnv("SERVER_PORT", "8888"),
		KeystorePath:     getEnv("KEYSTORE_PATH", "../certs/keystore.p12"),
		KeystorePassword: getEnv("KEYSTORE_PASSWORD", "changeit"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
