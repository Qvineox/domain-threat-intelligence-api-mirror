package core

import (
	"domain_threat_intelligence_api/cmd/core/entities"
)

type IBlacklistsService interface {
	RetrieveIPsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedIP, error)
	SaveIPs([]entities.BlacklistedIP) (int64, error)
	DeleteIP(id uint64) (int64, error)

	RetrieveDomainsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedDomain, error)
	SaveDomains([]entities.BlacklistedDomain) (int64, error)
	DeleteDomain(id uint64) (int64, error)

	RetrieveURLsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedURL, error)
	SaveURLs([]entities.BlacklistedURL) (int64, error)
	DeleteURL(id uint64) (int64, error)

	ImportFromSTIX2(bundles []entities.STIX2Bundle) (int64, []error)
	ImportFromCSV(data [][]string) (int64, []error)

	ExportToJSON(entities.BlacklistExportFilter) ([]byte, error)
	ExportToCSV(entities.BlacklistExportFilter) ([]byte, error)

	RetrieveStatistics() (ips int64, urls int64, domains int64)
}

type IBlacklistsRepo interface {
	SelectIPsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedIP, error)
	SaveIPs([]entities.BlacklistedIP) (int64, error)
	DeleteIP(id uint64) (int64, error)

	SelectDomainsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedDomain, error)
	SaveDomains([]entities.BlacklistedDomain) (int64, error)
	DeleteDomain(id uint64) (int64, error)

	SelectURLsByFilter(entities.BlacklistSearchFilter) ([]entities.BlacklistedURL, error)
	SaveURLs([]entities.BlacklistedURL) (int64, error)
	DeleteURL(id uint64) (int64, error)

	CountStatistics() (ips int64, urls int64, domains int64)
}
