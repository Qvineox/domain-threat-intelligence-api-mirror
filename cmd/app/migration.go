package app

import (
	"domain_threat_intelligence_api/cmd/core/entities"
	"gorm.io/gorm"
	"log/slog"
)

func runMigrations(database *gorm.DB) error {
	slog.Info("running migrations...")

	err := database.AutoMigrate(entities.BlacklistSource{}, entities.BlacklistedDomain{}, entities.BlacklistedIP{})
	if err != nil {
		return err
	}

	slog.Info("migrations completed successfully.")
	return nil
}
