package app

import (
	"domain_threat_intelligence_api/cmd/core/entities/agentEntities"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/networkEntities"
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
		userEntities.PlatformUserPermission{},
		userEntities.PlatformUser{},
		agentEntities.ScanAgent{},
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
	for _, r := range userEntities.DefaultUserPermissions {
		err := database.
			Where(userEntities.PlatformUserPermission{ID: r.ID}).
			Assign(userEntities.PlatformUserPermission{Name: r.Name, Description: r.Description}).
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
	user, err := userEntities.NewPlatformUser(
		"Root User",
		"root",
		"lysak.yaroslav00@yandex.ru",
		"passsalt",
		true)
	if err != nil {
		return err
	}

	err = user.SetPermissions(userEntities.DefaultUserPermissionPresets[3].RoleIDs)
	if err != nil {
		return err
	}

	err = database.
		Where(userEntities.PlatformUser{Login: user.Login}).
		Assign(userEntities.PlatformUser{IsActive: user.IsActive, Email: user.Email, PasswordHash: user.PasswordHash, Permissions: user.Permissions}).
		FirstOrCreate(&user).
		Error

	if err != nil {
		slog.Error("error creating root user: " + err.Error())
		return err
	}

	return nil
}
