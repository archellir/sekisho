package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/archellir/sekisho/internal/config"
	"github.com/archellir/sekisho/internal/server"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "Path to configuration file")
	version    = flag.Bool("version", false, "Show version information")
	genConfig  = flag.Bool("generate-config", false, "Generate default configuration to stdout")
)

const Version = "0.1.0"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("Sekisho (関所) %s\n", Version)
		os.Exit(0)
	}

	if *genConfig {
		if err := config.WriteDefault(os.Stdout); err != nil {
			log.Fatal("Failed to generate config:", err)
		}
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration:", err)
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		log.Fatal("Failed to create server:", err)
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := srv.Start(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Server failed to start:", err)
		}
	}()

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	} else {
		log.Println("Server stopped gracefully")
	}
}