package app

import (
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
	"domain_threat_intelligence_api/cmd/core/entities/scanEntities"
	"domain_threat_intelligence_api/cmd/core/entities/serviceDeskEntities"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"gorm.io/gorm"
	"log/slog"
)

func runMigrations(database *gorm.DB) error {
	slog.Info("running migrations...")

	err := database.AutoMigrate(
		serviceDeskEntities.ServiceDeskTicket{},
		blacklistEntities.BlacklistImportEvent{},
		blacklistEntities.BlacklistSource{},
		blacklistEntities.BlacklistedDomain{},
		blacklistEntities.BlacklistedIP{},
		blacklistEntities.BlacklistedURL{},
		blacklistEntities.BlacklistedEmail{},
		networkEntities.NetworkNodeType{},
		networkEntities.NetworkNode{},
		networkEntities.NetworkNodeScan{},
		networkEntities.NetworkNodeLink{},
		userEntities.PlatformUserRole{},
		userEntities.PlatformUser{},
		scanEntities.ScanAgent{},
	)

	if err != nil {
		return err
	}

	// populating dictionary tables
	err = migrateBlacklistSources(database)
	if err != nil {
		return err
	}

	err = migrateUserRoles(database)
	if err != nil {
		return err
	}

	err = createRootUser(database)
	if err != nil {
		return err
	}

	slog.Info("migrations completed successfully.")
	return nil
}

func migrateBlacklistSources(database *gorm.DB) error {
	for _, s := range blacklistEntities.DefaultSources {
		err := database.
			Where(blacklistEntities.BlacklistSource{ID: s.ID}).
			Assign(blacklistEntities.BlacklistSource{Name: s.Name, Description: s.Description}).
			FirstOrCreate(&s).
			Error

		if err != nil {
			slog.Error("error migrating sources schema: " + err.Error())
			return err
		}
	}

	return nil
}

func migrateUserRoles(database *gorm.DB) error {
	for _, r := range userEntities.DefaultUserRoles {
		err := database.
			Where(userEntities.PlatformUserRole{ID: r.ID}).
			Assign(userEntities.PlatformUserRole{Name: r.Name, Description: r.Description}).
			FirstOrCreate(&r).
			Error

		if err != nil {
			slog.Error("error migrating user roles schema: " + err.Error())
			return err
		}
	}

	return nil
}

func createRootUser(database *gorm.DB) error {
	rootUser := userEntities.PlatformUser{
		FullName:     "Root User",
		Login:        "root",
		PasswordHash: "missing_hash_value",
		IsActive:     true,
		DeletedAt:    gorm.DeletedAt{},
		Roles:        userEntities.DefaultUserRoles,
	}

	err := database.
		Where(userEntities.PlatformUser{Login: rootUser.Login}).
		Assign(userEntities.PlatformUser{IsActive: rootUser.IsActive, Roles: rootUser.Roles}).
		FirstOrCreate(&rootUser).
		Error

	if err != nil {
		slog.Error("error creating root user: " + err.Error())
		return err
	}

	return nil
}
