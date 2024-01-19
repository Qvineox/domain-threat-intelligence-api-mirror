package app

import (
	"domain_threat_intelligence_api/api/rest"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/cmd/core/services"
	"domain_threat_intelligence_api/configs"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log/slog"
)

func StartApp(cfg configs.Config) error {
	slog.Info("application starting...")
	slog.Info("establishing database connection...")

	// prepare database and run migrations
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name, cfg.Database.Timezone)
	dbConn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		slog.Error("failed to connect database: " + err.Error())
		panic(err)
	} else {
		slog.Info("database connected")
	}

	err = runMigrations(dbConn)
	if err != nil {
		return err
	}

	// creating repositories and services
	domainServices := rest.Services{
		BlacklistService: services.NewBlackListsServiceImpl(repos.NewBlacklistsRepoImpl(dbConn)),
	}

	slog.Info("web server starting...")

	webServer, err := rest.NewHTTPServer(cfg.WebServer.Host, cfg.WebServer.Port, cfg.WebServer.Swagger, domainServices, []string{cfg.WebServer.AllowedOrigin})
	err = webServer.Start()
	if err != nil {
		slog.Info("web server stopped with error: " + err.Error())
		return err
	}

	slog.Info("application stopping...")

	return nil
}
