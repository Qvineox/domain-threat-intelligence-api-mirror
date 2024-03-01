package main

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/cmd/loggers"
	"domain_threat_intelligence_api/configs"
	"fmt"
	"log/slog"
)

func main() {
	loggers.SetDefaultLogger(slog.LevelInfo)

	// reading configuration
	staticCfg, err := configs.NewStaticConfig()
	if err != nil {
		panic(err)
		return
	}

	dynamicCfg, err, dynamicUpdateChan := configs.NewDynamicConfigProvider()
	if err != nil {
		panic(err)
		return
	}

	var level slog.Level

	switch staticCfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warning":
		level = slog.LevelWarn
	default:
		slog.Warn(fmt.Sprintf("log level '%s' not supported", staticCfg.Logging.Level))
		level = slog.LevelInfo
	}

	loggers.SetDefaultLogger(level)

	go dynamicCfg.StartWatcher()

	// starting the application
	err = app.StartApp(staticCfg, dynamicCfg, dynamicUpdateChan)
	if err != nil {
		panic(err)
		return
	}

	return
}
