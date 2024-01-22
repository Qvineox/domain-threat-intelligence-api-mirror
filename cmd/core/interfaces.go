package core

import (
	"domain_threat_intelligence_api/cmd/core/entities"
	"github.com/jackc/pgtype"
	"time"
)

type IBlacklistsService interface {
	RetrieveIPsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedIP, error)
	SaveIPs([]entities.BlacklistedIP) (int64, error)
	DeleteIP(uuid pgtype.UUID) (int64, error)

	RetrieveDomainsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedDomain, error)
	SaveDomains([]entities.BlacklistedDomain) (int64, error)
	DeleteDomain(uuid pgtype.UUID) (int64, error)

	RetrieveURLsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedURL, error)
	SaveURLs([]entities.BlacklistedURL) (int64, error)
	DeleteURL(uuid pgtype.UUID) (int64, error)

	RetrieveHostsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedHost, error)

	ImportFromSTIX2(bundles []entities.STIX2Bundle) (int64, []error)
	ImportFromCSV(data [][]string) (int64, []error)

	ExportToJSON(entities.BlacklistExportFilter) ([]byte, error)
	ExportToCSV(entities.BlacklistExportFilter) ([]byte, error)

	RetrieveTotalStatistics() (ips int64, urls int64, domains int64)
	RetrieveByDateStatistics(startDate, endDate time.Time) ([]entities.BlacklistedByDate, error)

	RetrieveAllSources() ([]entities.BlacklistSource, error)
}

type IBlacklistsRepo interface {
	SelectIPsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedIP, error)
	SaveIPs([]entities.BlacklistedIP) (int64, error)
	DeleteIP(uuid pgtype.UUID) (int64, error)

	SelectDomainsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedDomain, error)
	SaveDomains([]entities.BlacklistedDomain) (int64, error)
	DeleteDomain(uuid pgtype.UUID) (int64, error)

	SelectURLsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedURL, error)
	SaveURLs([]entities.BlacklistedURL) (int64, error)
	DeleteURL(uuid pgtype.UUID) (int64, error)

	SelectHostsUnionByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedHost, error)

	CountStatistics() (ips int64, urls int64, domains int64)
	SelectByDateStatistics(startDate, endDate time.Time) ([]entities.BlacklistedByDate, error)

	SelectAllSources() ([]entities.BlacklistSource, error)
}

type IUsersService interface {
	// CreateUser creates only new entities.PlatformUser, returns error if user exists, ignores defined UUID
	CreateUser(login, password, fullName, email string) (pgtype.UUID, error)

	// SaveUser updates only existing entities.PlatformUser, returns error if user doesn't exist, UUID should be defined.
	// This method doesn't update user password, use ResetPassword or ChangePassword
	SaveUser(user entities.PlatformUser) (pgtype.UUID, error)

	DeleteUser(uuid pgtype.UUID) error
	RetrieveUsers() ([]entities.PlatformUser, error)
	RetrieveUser(uuid pgtype.UUID) (entities.PlatformUser, error)

	RetrieveRoles() ([]entities.PlatformUserRole, error)

	// ResetPassword is used to send recovery messages to users
	ResetPassword(uuid pgtype.UUID) error

	// ChangePassword allows to set new password for user. Can be used by admin and user itself
	ChangePassword(uuid pgtype.UUID, oldPassword, newPassword string) error
}

type IUsersRepo interface {
	InsertUser(user entities.PlatformUser) (pgtype.UUID, error)
	UpdateUser(user entities.PlatformUser) (pgtype.UUID, error)
	DeleteUser(uuid pgtype.UUID) error
	SelectUsers() ([]entities.PlatformUser, error)
	SelectUser(uuid pgtype.UUID) (entities.PlatformUser, error)

	SelectRoles() ([]entities.PlatformUserRole, error)

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
