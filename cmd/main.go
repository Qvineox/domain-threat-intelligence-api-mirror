package main

import (
	"domain_threat_intelligence_api/cmd/app"
	"domain_threat_intelligence_api/configs"
)

func main() {
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

	go dynamicCfg.StartWatcher()

	// starting the application
	err = app.StartApp(staticCfg, dynamicCfg, dynamicUpdateChan)
	if err != nil {
		panic(err)
		return
	}

	return
}
