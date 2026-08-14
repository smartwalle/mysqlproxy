package main

import (
	"log"

	"github.com/smartwalle/bootstrap"
	"github.com/smartwalle/mysqlproxy/internal/config"
	"github.com/smartwalle/mysqlproxy/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	app := bootstrap.New(
		bootstrap.WithServers(server.New(cfg)),
	)
	if err = app.Run(); err != nil {
		log.Fatalf("run application: %v", err)
	}
}
