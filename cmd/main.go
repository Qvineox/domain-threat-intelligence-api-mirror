package main

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/configs"
	"log/slog"
)

func main() {
	// reading configuration
	staticCfg, err := configs.NewStaticConfig()
	if err != nil {
		panic(err)
		return
	}

	dynamicCfg, err := configs.NewDynamicConfig()
	if err != nil {
		panic(err)
		return
	}

	value, err := dynamicCfg.GetValue(configs.NaumenClientKey)
	if err != nil {
		slog.Warn(err.Error())
	}

	slog.Info(value)

	// starting the application
	err = app.StartApp(staticCfg)
	if err != nil {
		panic(err)
		return
	}

	return
}
