package core

import (
	"domain_threat_intelligence_api/cmd/core/entities"
)

type IBlacklistsService interface {
	RetrieveIPsByFilter(entities.BlacklistFilter) ([]entities.BlacklistedIP, error)
	SaveIPs([]entities.BlacklistedIP) (int64, error)
	DeleteIP(id uint64) (int64, error)

	RetrieveDomainsByFilter(entities.BlacklistFilter) ([]entities.BlacklistedDomain, error)
	SaveDomains([]entities.BlacklistedDomain) (int64, error)
	DeleteDomain(id uint64) (int64, error)
}

type IBlacklistsRepo interface {
	SelectIPsByFilter(entities.BlacklistFilter) ([]entities.BlacklistedIP, error)
	SaveIPs([]entities.BlacklistedIP) (int64, error)
	DeleteIP(id uint64) (int64, error)

	SelectDomainsByFilter(entities.BlacklistFilter) ([]entities.BlacklistedDomain, error)
	SaveDomains([]entities.BlacklistedDomain) (int64, error)
	DeleteDomain(id uint64) (int64, error)
}
