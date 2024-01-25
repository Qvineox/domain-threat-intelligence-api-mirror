package core

import (
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"github.com/jackc/pgtype"
	"time"
)

type IBlacklistsService interface {
	RetrieveIPsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedIP, error)
	SaveIPs([]blacklistEntities.BlacklistedIP) (int64, error)
	DeleteIP(uuid pgtype.UUID) (int64, error)

	RetrieveDomainsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedDomain, error)
	SaveDomains([]blacklistEntities.BlacklistedDomain) (int64, error)
	DeleteDomain(uuid pgtype.UUID) (int64, error)

	RetrieveURLsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedURL, error)
	SaveURLs([]blacklistEntities.BlacklistedURL) (int64, error)
	DeleteURL(uuid pgtype.UUID) (int64, error)

	RetrieveEmailsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedEmail, error)
	SaveEmails([]blacklistEntities.BlacklistedEmail) (int64, error)
	DeleteEmail(uuid pgtype.UUID) (int64, error)

	RetrieveImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error)
	RetrieveImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error)
	DeleteImportEvent(id uint64) (int64, error)

	RetrieveHostsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error)

	ImportFromSTIX2(bundles []blacklistEntities.STIX2Bundle) (int64, []error)
	ImportFromCSV(data [][]string, discoveredAt time.Time) (int64, []error)

	ExportToJSON(blacklistEntities.BlacklistExportFilter) ([]byte, error)
	ExportToCSV(blacklistEntities.BlacklistExportFilter) ([]byte, error)

	RetrieveTotalStatistics() (ips int64, urls int64, domains int64)
	RetrieveByDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)

	RetrieveAllSources() ([]blacklistEntities.BlacklistSource, error)
}

type IBlacklistsRepo interface {
	SelectIPsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedIP, error)
	SaveIPs([]blacklistEntities.BlacklistedIP) (int64, error)
	DeleteIP(uuid pgtype.UUID) (int64, error)

	SelectDomainsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedDomain, error)
	SaveDomains([]blacklistEntities.BlacklistedDomain) (int64, error)
	DeleteDomain(uuid pgtype.UUID) (int64, error)

	SelectURLsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedURL, error)
	SaveURLs([]blacklistEntities.BlacklistedURL) (int64, error)
	DeleteURL(uuid pgtype.UUID) (int64, error)

	SelectEmailsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedEmail, error)
	SaveEmails([]blacklistEntities.BlacklistedEmail) (int64, error)
	DeleteEmail(uuid pgtype.UUID) (int64, error)

	CreateImportEvent(event blacklistEntities.BlacklistImportEvent) (blacklistEntities.BlacklistImportEvent, error)
	SelectImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error)
	SelectImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error)
	DeleteImportEvent(id uint64) (int64, error)

	SelectHostsUnionByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error)

	CountStatistics() (ips int64, urls int64, domains int64)
	SelectByDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)

	SelectAllSources() ([]blacklistEntities.BlacklistSource, error)
}

type IUsersService interface {
	// CreateUser creates only new entities.PlatformUser, returns error if user exists, ignores defined UUID
	CreateUser(login, password, fullName, email string) (pgtype.UUID, error)

	// SaveUser updates only existing entities.PlatformUser, returns error if user doesn't exist, UUID should be defined.
	// This method doesn't update user password, use ResetPassword or ChangePassword
	SaveUser(user userEntities.PlatformUser) (pgtype.UUID, error)

	DeleteUser(uuid pgtype.UUID) error
	RetrieveUsers() ([]userEntities.PlatformUser, error)
	RetrieveUser(uuid pgtype.UUID) (userEntities.PlatformUser, error)

	RetrieveRoles() ([]userEntities.PlatformUserRole, error)

	// ResetPassword is used to send recovery messages to users
	ResetPassword(uuid pgtype.UUID) error

	// ChangePassword allows to set new password for user. Can be used by admin and user itself
	ChangePassword(uuid pgtype.UUID, oldPassword, newPassword string) error
}

type IUsersRepo interface {
	InsertUser(user userEntities.PlatformUser) (pgtype.UUID, error)
	UpdateUser(user userEntities.PlatformUser) (pgtype.UUID, error)
	DeleteUser(uuid pgtype.UUID) error
	SelectUsers() ([]userEntities.PlatformUser, error)
	SelectUser(uuid pgtype.UUID) (userEntities.PlatformUser, error)

	SelectRoles() ([]userEntities.PlatformUserRole, error)

	// UpdatePasswordHash is used only to update user password hash. Must be used when resetting or changing password
	UpdatePasswordHash(uuid pgtype.UUID, hash string) error
}

type IAuthService interface {
	RegisterNewUser(login, password, fullName, email string) (pgtype.UUID, error)
	ConfirmEmail(confirmationUUID pgtype.UUID) error

	Login(login, password string) (accessToken, refreshToken string, err error)
	Logout(uuid pgtype.UUID) error

	Refresh(token string) (accessToken, refreshToken string, err error)
}

// ISystemStateService holds collection of services that provide info about system configuration, state and status
type ISystemStateService interface {
	RetrieveDynamicConfig() ([]byte, error)
	SaveDynamicConfigVariable(key, value string) error
	ReturnToDefault() error
}
