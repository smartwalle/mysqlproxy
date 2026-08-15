package main

import (
	"log"

	"github.com/smartwalle/bootstrap"
	"github.com/smartwalle/mysqlproxy"
)

func main() {
	cfg, err := mysqlproxy.LoadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	app := bootstrap.New(
		bootstrap.WithServers(mysqlproxy.New(cfg)),
	)
	if err = app.Run(); err != nil {
		log.Fatalf("run application: %v", err)
	}
}
