package main

import (
	"log"

	"github.com/smartwalle/mysqlproxy/internal/config"
	"github.com/smartwalle/mysqlproxy/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	srv := server.New(cfg)
	if err = srv.Listen(); err != nil {
		log.Fatalf("start server: %v", err)
	}
}
