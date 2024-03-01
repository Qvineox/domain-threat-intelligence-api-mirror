package app

import (
	"domain_threat_intelligence_api/api/rest"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/repos"
	"domain_threat_intelligence_api/cmd/core/services"
	"domain_threat_intelligence_api/cmd/integrations/naumen"
	"domain_threat_intelligence_api/cmd/mail"
	"domain_threat_intelligence_api/cmd/scheduler"
	"domain_threat_intelligence_api/configs"
	"fmt"
	slogGorm "github.com/orandin/slog-gorm"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log/slog"
	"os"
)

func StartApp(staticCfg configs.StaticConfig, dynamicCfg *configs.DynamicConfigProvider, dynamicUpdateChan chan bool) error {
	slog.Info("application starting...")
	slog.Info("establishing database connection...")

	// prepare database, logger and run migrations
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	l = l.With(slog.String("log_type", "database"))

	dbLogger := slogGorm.New(
		slogGorm.WithLogger(l),
		slogGorm.SetLogLevel(slogGorm.ErrorLogType, slog.LevelError),
		slogGorm.SetLogLevel(slogGorm.SlowQueryLogType, slog.LevelWarn),
		slogGorm.SetLogLevel(slogGorm.DefaultLogType, slog.LevelInfo),
	)

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", staticCfg.Database.Host, staticCfg.Database.Port, staticCfg.Database.User, staticCfg.Database.Password, staticCfg.Database.Name, staticCfg.Database.Timezone)
	dbConn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: dbLogger,
	})
	if err != nil {
		slog.Error("failed to connect database: " + err.Error())
		panic(err)
	} else {
		slog.Info("database connected")
	}

	err = Migrate(dbConn)
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

	jobsRepo := repos.NewJobsRepoImpl(dbConn)
	nodesRepo := repos.NewNetworkNodesRepoImpl(dbConn)
	agentsRepo := repos.NewAgentsRepoImpl(dbConn)

	domainServices.JobsService = services.NewJobsServiceImpl(jobsRepo)

	const queueLimit = 1000 // TODO: add to config

	queue := jobEntities.NewQueue(queueLimit)
	sch, err := scheduler.NewScheduler(queue, agentsRepo, nodesRepo)

	domainServices.AgentsService = services.NewAgentsServiceImpl(agentsRepo, sch)
	domainServices.QueueService = services.NewQueueServiceImpl(domainServices.JobsService, nodesRepo, agentsRepo, queue, sch)

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
