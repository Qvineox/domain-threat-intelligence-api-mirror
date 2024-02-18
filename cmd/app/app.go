package app

import (
	"domain_threat_intelligence_api/api/rest"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/cmd/core/services"
	"domain_threat_intelligence_api/cmd/integrations/naumen"
	"domain_threat_intelligence_api/cmd/mail"
	"domain_threat_intelligence_api/configs"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"log/slog"
	"os"
	"time"
)

func StartApp(staticCfg configs.StaticConfig, dynamicCfg *configs.DynamicConfigProvider, dynamicUpdateChan chan bool) error {
	slog.Info("application starting...")
	slog.Info("establishing database connection...")

	// prepare database and run migrations
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,   // Slow SQL threshold
			LogLevel:                  logger.Silent, // Log level
			IgnoreRecordNotFoundError: true,          // Ignore ErrRecordNotFound error for logger
			ParameterizedQueries:      true,          // Don't include params in the SQL log
			Colorful:                  false,         // Disable color
		},
	)

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", staticCfg.Database.Host, staticCfg.Database.Port, staticCfg.Database.User, staticCfg.Database.Password, staticCfg.Database.Name, staticCfg.Database.Timezone)
	dbConn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
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

	// integrations and mail client
	domainServices.ServiceDeskService = naumen.NewServiceDeskClient(repos.NewServiceDeskRepoImpl(dbConn), dynamicCfg)
	domainServices.SMTPService = mail.NewSMTPClient(dynamicCfg, dynamicUpdateChan)

	// creating repositories and services
	domainServices.BlacklistService = services.NewBlackListsServiceImpl(repos.NewBlacklistsRepoImpl(dbConn), domainServices.ServiceDeskService)
	domainServices.SystemStateService = services.NewSystemStateServiceImpl(dynamicCfg)

	usersRepo := repos.NewUsersRepoImpl(dbConn)
	domainServices.AuthService = services.NewAuthServiceImpl(usersRepo, domainServices.SMTPService, "salt", staticCfg.WebServer.Security.Domain, staticCfg.WebServer.Security.AllowedOrigins[0])
	domainServices.UsersService = services.NewUsersServiceImpl(usersRepo, domainServices.AuthService)

	// web server configuration
	webServer, err := rest.NewHTTPServer(
		staticCfg.WebServer.Host,
		staticCfg.WebServer.API.Path,
		staticCfg.WebServer.Security.AllowedOrigins,
		staticCfg.WebServer.Port,
		domainServices)

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
