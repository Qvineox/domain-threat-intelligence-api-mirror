package app

import (
	"domain_threat_intelligence_api/api/rest"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/cmd/core/services"
	"domain_threat_intelligence_api/cmd/integrations/naumen"
	"domain_threat_intelligence_api/configs"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log/slog"
)

func StartApp(staticCfg configs.StaticConfig, dynamicCfg *configs.DynamicConfigProvider) error {
	slog.Info("application starting...")
	slog.Info("establishing database connection...")

	// prepare database and run migrations
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", staticCfg.Database.Host, staticCfg.Database.Port, staticCfg.Database.User, staticCfg.Database.Password, staticCfg.Database.Name, staticCfg.Database.Timezone)
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

	// domain services initialization
	domainServices := rest.Services{}

	// integrations
	domainServices.ServiceDeskService = naumen.NewServiceDeskClient(repos.NewServiceDeskRepoImpl(dbConn), dynamicCfg)

	// creating repositories and services
	domainServices.BlacklistService = services.NewBlackListsServiceImpl(repos.NewBlacklistsRepoImpl(dbConn), domainServices.ServiceDeskService)
	domainServices.SystemStateService = services.NewSystemStateServiceImpl(dynamicCfg)

	usersRepo := repos.NewUsersRepoImpl(dbConn)
	domainServices.AuthService = services.NewAuthServiceImpl(usersRepo, "salt", staticCfg.WebServer.Security.Domain)
	domainServices.UsersService = services.NewUsersServiceImpl(usersRepo, domainServices.AuthService)

	// web server configuration
	webServer, err := rest.NewHTTPServer(
		staticCfg.WebServer.Host,
		staticCfg.WebServer.API.Path,
		staticCfg.WebServer.Port,
		domainServices)

	webServer.ConfigureCORS(staticCfg.WebServer.Security.AllowedOrigins)

	if staticCfg.WebServer.Swagger.Enabled {
		webServer.EnableSwagger(
			staticCfg.WebServer.Swagger.Host,
			staticCfg.WebServer.Swagger.Version,
			staticCfg.WebServer.API.Path,
		)
	}

	slog.Info("web server starting...")
	err = webServer.Start()
	if err != nil {
		slog.Info("web server stopped with error: " + err.Error())
		return err
	}

	slog.Info("application stopping...")

	return nil
}
