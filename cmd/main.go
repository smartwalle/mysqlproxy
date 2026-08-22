package main

import (
	"log/slog"
	"os"
	"time"

	"github.com/smartwalle/bootstrap"
	"github.com/smartwalle/mysqlproxy"
)

func main() {
	cfg, err := mysqlproxy.LoadConfig(nil)
	if err != nil {
		slog.Error("load config failed", "error", err)
		os.Exit(1)
	}

	app := bootstrap.New(
		bootstrap.WithServers(mysqlproxy.New(cfg)),
		bootstrap.WithStopTimeout(time.Second),
	)
	if err = app.Run(); err != nil {
		slog.Error("run application failed", "error", err)
		os.Exit(1)
	}
}
