package app

import (
	"domain_threat_intelligence_api/configs"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log/slog"
)

func StartApp(cfg configs.Config) error {
	slog.Info("application starting...")
	slog.Info("establishing database connection...")

	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s database=%s sslmode=disable TimeZone=%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name, cfg.Database.Timezone)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		slog.Error("failed to connect database: " + err.Error())
		panic(err)
	} else {
		slog.Info("database connected")
	}

	// prepare database and run migrations

	err = runMigrations(db)
	if err != nil {
		slog.Error("error during migration: " + err.Error())
		return err
	}

	return nil
}
