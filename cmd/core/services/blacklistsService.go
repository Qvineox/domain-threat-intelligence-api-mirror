package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities"
)

type BlackListsServiceImpl struct {
	repo core.IBlacklistsRepo
}

func NewBlackListsServiceImpl(repo core.IBlacklistsRepo) *BlackListsServiceImpl {
	return &BlackListsServiceImpl{repo: repo}
}

func (s *BlackListsServiceImpl) RetrieveIPsByFilter(filter entities.BlacklistFilter) ([]entities.BlacklistedIP, error) {
	return s.repo.SelectIPsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveIPs(ips []entities.BlacklistedIP) (int64, error) {
	return s.repo.SaveIPs(ips)
}

func (s *BlackListsServiceImpl) DeleteIP(id uint64) (int64, error) {
	return s.repo.DeleteIP(id)
}

func (s *BlackListsServiceImpl) RetrieveDomainsByFilter(filter entities.BlacklistFilter) ([]entities.BlacklistedDomain, error) {
	return s.repo.SelectDomainsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveDomains(domains []entities.BlacklistedDomain) (int64, error) {
	return s.repo.SaveDomains(domains)
}

func (s *BlackListsServiceImpl) DeleteDomain(id uint64) (int64, error) {
	return s.repo.DeleteDomain(id)
}
