package main

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/configs"
)

func main() {
	// reading configuration
	cfg, err := configs.ReadConfig()
	if err != nil {
		panic(err)
		return
	}

	// starting the application
	err = app.StartApp(cfg)
	if err != nil {
		panic(err)
		return
	}

	return
}
