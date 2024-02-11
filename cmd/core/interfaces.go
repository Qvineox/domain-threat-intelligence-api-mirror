package core

import (
	"domain_threat_intelligence_api/cmd/core/entities/authEntities"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/serviceDeskEntities"
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

	SaveImportEvent(event blacklistEntities.BlacklistImportEvent) (blacklistEntities.BlacklistImportEvent, error)
	RetrieveImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error)
	RetrieveImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error)
	DeleteImportEvent(id uint64) (int64, error)

	RetrieveHostsByFilter(blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error)

	ImportFromSTIX2(bundles []blacklistEntities.STIX2Bundle, extractAll bool) (blacklistEntities.BlacklistImportEvent, error)
	ImportFromCSV(data [][]string, discoveredAt time.Time, extractAll bool) (blacklistEntities.BlacklistImportEvent, error)

	ExportToJSON(blacklistEntities.BlacklistSearchFilter) ([]byte, error)
	ExportToCSV(blacklistEntities.BlacklistSearchFilter) ([]byte, error)
	ExportToNaumen(filter blacklistEntities.BlacklistSearchFilter) (serviceDeskEntities.ServiceDeskTicket, error)

	RetrieveTotalStatistics() (ips int64, urls int64, domains int64, emails int64)
	RetrieveByCreationDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)
	RetrieveByDiscoveryDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)

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

	SaveImportEvent(event blacklistEntities.BlacklistImportEvent) (blacklistEntities.BlacklistImportEvent, error)
	SelectImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error)
	SelectImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error)
	DeleteImportEvent(id uint64) (int64, error)

	SelectHostsUnionByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error)

	CountStatistics() (ips int64, urls int64, domains int64, emails int64)
	SelectByCreationDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)
	SelectByDiscoveryDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error)

	SelectAllSources() ([]blacklistEntities.BlacklistSource, error)
}

type IUsersService interface {
	// SaveUser updates only existing entities.PlatformUser, returns error if user doesn't exist, ID must be defined.
	// This method doesn't update user password, use ResetPassword or ChangePassword
	SaveUser(user userEntities.PlatformUser, permissionIDs []uint64) error

	CreateUser(user userEntities.PlatformUser, password string, permissionIDs []uint64) (uint64, error)

	DeleteUser(id uint64) (int64, error)
	RetrieveUsers() ([]userEntities.PlatformUser, error)
	RetrieveUser(id uint64) (userEntities.PlatformUser, error)

	RetrievePermissions() ([]userEntities.PlatformUserPermission, error)
	RetrievePermissionPresets() []userEntities.PlatformUserRolesPreset

	// ResetPassword is used to send recovery messages to users
	ResetPassword(id uint64) error

	// ChangePassword allows to set new password for user. Can be used by admin and user itself
	ChangePassword(id uint64, oldPassword, newPassword string) error
}

type IUsersRepo interface {
	InsertUser(user userEntities.PlatformUser) (uint64, error)
	UpdateUser(user userEntities.PlatformUser) error
	DeleteUser(id uint64) (int64, error)

	SelectUsers() ([]userEntities.PlatformUser, error)
	SelectUser(id uint64) (userEntities.PlatformUser, error)
	SelectUserByLogin(login string) (userEntities.PlatformUser, error)

	SelectPermissions() ([]userEntities.PlatformUserPermission, error)

	// UpdateUserWithPasswordHash is used only to update user password hash. Must be used when resetting or changing password
	UpdateUserWithPasswordHash(user userEntities.PlatformUser) error
}

type IAuthService interface {
	ConfirmEmail(confirmationUUID pgtype.UUID) error

	// Register creates new entities.PlatformUser, returns error if user exists, ignores defined ID
	Register(login, password, fullName, email string, roleIDs []uint64) (uint64, error)
	Login(login, password string) (accessToken, refreshToken string, err error)
	Logout(refreshToken string) error

	ChangePassword(user userEntities.PlatformUser, oldPassword, newPassword string) (userEntities.PlatformUser, error)
	ResetPassword(user userEntities.PlatformUser) (userEntities.PlatformUser, error)

	Validate(accessToken string) (claims authEntities.AccessTokenClaims, err error)
	Refresh(refreshToken string) (accessToken, newRefreshToken string, err error)

	GetDomain() string
}

// ISystemStateService holds collection of services that provide info about system configuration, state and status
type ISystemStateService interface {
	RetrieveDynamicConfig() ([]byte, error)
	ReturnToDefault() error

	UpdateSMTPConfig(enabled bool, host, user, password, sender string, useTLS bool) error
	UpdateNSDCredentials(enabled bool, host, clientKey string, clientID, clientGroupID uint64) error
	UpdateNSDBlacklistServiceConfig(id, slm uint64, callType string, types []string) error
}

type IServiceDeskService interface {
	IsAvailable() bool

	RetrieveTicketsByFilter(filter serviceDeskEntities.ServiceDeskSearchFilter) ([]serviceDeskEntities.ServiceDeskTicket, error)
	DeleteTicket(id uint64) error

	// SendBlacklistedHosts sends new ticket to service desk
	SendBlacklistedHosts([]blacklistEntities.BlacklistedHost) (ticket serviceDeskEntities.ServiceDeskTicket, err error)
}

type IServiceDeskRepo interface {
	SaveTicket(ticket serviceDeskEntities.ServiceDeskTicket) (serviceDeskEntities.ServiceDeskTicket, error)
	SelectTicketsByFilter(filter serviceDeskEntities.ServiceDeskSearchFilter) ([]serviceDeskEntities.ServiceDeskTicket, error)
	DeleteTicket(id uint64) error
	//SelectTicket(id uint64)
}
