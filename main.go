package main

import (
	"log/slog"
	"os"

	"github.com/rsmanito/bank-api/config"
	"github.com/rsmanito/bank-api/server"
	"github.com/rsmanito/bank-api/storage"
)

func main() {
	cfg := config.Load()

	l := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(l)

	st := storage.New(cfg)

	s := server.New(st, cfg)

	go s.Run(cfg.Port)

	slog.Info("Running API", "port", cfg.Port)

	select {}
}
