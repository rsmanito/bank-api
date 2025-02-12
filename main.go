package main

import (
	"log"

	"github.com/rsmanito/bank-api/config"
	"github.com/rsmanito/bank-api/server"
	"github.com/rsmanito/bank-api/storage"
)

func main() {
	cfg := config.Load()

	st := storage.New()

	s := server.New(st, cfg)

	go s.Run(cfg.Port)

	log.Default().Printf("Running on port %s", cfg.Port)

	select {}
}
