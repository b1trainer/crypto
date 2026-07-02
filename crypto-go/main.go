package main

import (
	"context"
	"crypto-go/config"
	"crypto-go/crypto"
	"crypto-go/db"
	"crypto-go/handlers"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := config.Load()
	database, err := db.Init()
	if err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}
	defer database.Close()

	log.Println("Database initialized")

	certs, err := config.LoadKeystore(cfg.KeystorePath, cfg.KeystorePassword)
	if err != nil {
		log.Fatalf("failed to load keystore: %v", err)
	}

	log.Println("Keystore loaded")

	sigService := crypto.NewSignatureService(certs.PrivateKey, certs.X509)
	encService := crypto.NewEncryptionService(certs.PrivateKey, certs.PublicKey)

	log.Println("Services initialized")

	handler, err := handlers.NewHandler(database, sigService, encService, certs)
	if err != nil {
		log.Fatalf("failed to initialize http handlers: %v", err)
	}

	log.Println("Handlers initialized")

	// мультиплексор, роутер http запросов
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/crypto/sign", handler.Sign)
	mux.HandleFunc("/v2/crypto/verify", handler.Verify)
	mux.HandleFunc("/v2/crypto/encrypt", handler.Encrypt)
	mux.HandleFunc("/v2/crypto/decrypt", handler.Decrypt)
	mux.HandleFunc("/v2/crypto/hash", handler.Hash)
	mux.HandleFunc("/v2/crypto/operations", handler.Operations)

	log.Println("Router initialized")

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("Server instance created, port:", cfg.Port)

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		log.Println("Server shutting down")
		_ = server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("failed to start http server: %v", err)
	}

}
