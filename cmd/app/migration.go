package app

import (
	"domain_threat_intelligence_api/cmd/core/entities"
	"gorm.io/gorm"
	"log/slog"
)

func runMigrations(database *gorm.DB) error {
	slog.Info("running migrations...")

	err := database.AutoMigrate(
		entities.BlacklistSource{},
		entities.BlacklistedDomain{},
		entities.BlacklistedIP{},
		entities.BlacklistedURL{},
		entities.NetworkNodeType{},
		entities.NetworkNode{},
		entities.NetworkNodeScan{},
		entities.NetworkNodeLink{},
		entities.PlatformUserRole{},
		entities.PlatformUser{},
		entities.ScanAgent{},
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
	for _, s := range entities.DefaultSources {
		err := database.
			Where(entities.BlacklistSource{Model: gorm.Model{ID: s.ID}}).
			Assign(entities.BlacklistSource{Name: s.Name, Description: s.Description}).
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
	for _, r := range entities.DefaultUserRoles {
		err := database.
			Where(entities.PlatformUserRole{Model: gorm.Model{ID: r.ID}}).
			Assign(entities.PlatformUserRole{Name: r.Name, Description: r.Description}).
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
	rootUser := entities.PlatformUser{
		FullName:     "Root User",
		Login:        "root",
		PasswordHash: "missing_hash_value",
		IsActive:     true,
		DeletedAt:    gorm.DeletedAt{},
		Roles:        entities.DefaultUserRoles,
	}

	err := database.
		Where(entities.PlatformUser{Login: rootUser.Login}).
		Assign(entities.PlatformUser{IsActive: rootUser.IsActive, Roles: rootUser.Roles}).
		FirstOrCreate(&rootUser).
		Error

	if err != nil {
		slog.Error("error creating root user: " + err.Error())
		return err
	}

	return nil
}
