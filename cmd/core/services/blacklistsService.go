package services

import (
	"bytes"
	"crypto/md5"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgtype"
	"strings"
	"sync"
	"time"
)

type BlackListsServiceImpl struct {
	repo core.IBlacklistsRepo
}

func (s *BlackListsServiceImpl) RetrieveURLsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedURL, error) {
	return s.repo.SelectURLsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveURLs(urls []blacklistEntities.BlacklistedURL) (int64, error) {
	if len(urls) == 0 {
		return 0, nil
	}

	// add hashes to URLs
	for i, v := range urls {
		hash := md5.Sum([]byte(v.URL))
		v.MD5 = hex.EncodeToString(hash[:])

		urls[i] = v
	}

	return s.repo.SaveURLs(urls)
}

func (s *BlackListsServiceImpl) DeleteURL(uuid pgtype.UUID) (int64, error) {
	return s.repo.DeleteURL(uuid)
}

func NewBlackListsServiceImpl(repo core.IBlacklistsRepo) *BlackListsServiceImpl {
	return &BlackListsServiceImpl{repo: repo}
}

func (s *BlackListsServiceImpl) RetrieveIPsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedIP, error) {
	return s.repo.SelectIPsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveIPs(ips []blacklistEntities.BlacklistedIP) (int64, error) {
	if len(ips) == 0 {
		return 0, nil
	}

	return s.repo.SaveIPs(ips)
}

func (s *BlackListsServiceImpl) DeleteIP(uuid pgtype.UUID) (int64, error) {
	return s.repo.DeleteIP(uuid)
}

func (s *BlackListsServiceImpl) RetrieveDomainsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedDomain, error) {
	return s.repo.SelectDomainsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveDomains(domains []blacklistEntities.BlacklistedDomain) (int64, error) {
	if len(domains) == 0 {
		return 0, nil
	}

	return s.repo.SaveDomains(domains)
}

func (s *BlackListsServiceImpl) DeleteDomain(uuid pgtype.UUID) (int64, error) {
	return s.repo.DeleteDomain(uuid)
}

func (s *BlackListsServiceImpl) RetrieveHostsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error) {
	return s.repo.SelectHostsUnionByFilter(filter)
}

func (s *BlackListsServiceImpl) ImportFromSTIX2(bundles []blacklistEntities.STIX2Bundle) (int64, []error) {
	var ipMap = make(map[string]*blacklistEntities.BlacklistedIP)
	var domainMap = make(map[string]*blacklistEntities.BlacklistedDomain)
	var urlMap = make(map[string]*blacklistEntities.BlacklistedURL)

	var errors_ []error

	for bIndex, b := range bundles {
		for iIndex, object := range b.Objects {
			if object.Type != "indicator" { // skip all other object types
				continue
			}

			i, d, u, err := object.ToBlacklisted()
			if err != nil {
				errors_ = append(errors_, errors.New(fmt.Sprintf("error in bundle #%d, value #%d; error: %s", bIndex, iIndex, err.Error())))
			}

			if i != nil {
				ipMap[i.IPAddress.IPNet.String()] = i
			}

			if d != nil {
				domainMap[d.URN] = d
			}

			if u != nil {
				urlMap[u.URL] = u
			}
		}
	}

	// async saving of all host types
	var rowsTotal int64 = 0
	wg := sync.WaitGroup{}
	wg.Add(3)

	go func() {
		var ips = make([]blacklistEntities.BlacklistedIP, 0, len(ipMap))
		for _, v := range ipMap {
			ips = append(ips, *v)
		}

		rows, err := s.SaveIPs(ips)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var urls = make([]blacklistEntities.BlacklistedURL, 0, len(urlMap))
		for _, v := range urlMap {
			urls = append(urls, *v)
		}

		rows, err := s.SaveURLs(urls)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var domains = make([]blacklistEntities.BlacklistedDomain, 0, len(domainMap))
		for _, v := range domainMap {
			domains = append(domains, *v)
		}

		rows, err := s.SaveDomains(domains)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	wg.Wait()

	return rowsTotal, errors_
}

func (s *BlackListsServiceImpl) ImportFromCSV(data [][]string) (int64, []error) {
	var ipMap = make(map[string]*blacklistEntities.BlacklistedIP)
	var domainMap = make(map[string]*blacklistEntities.BlacklistedDomain)
	var urlMap = make(map[string]*blacklistEntities.BlacklistedURL)

	var errors_ []error

	// read all lines, remove header
	for _, r := range data[1:] {
		t, v, s_, c := r[0], r[1], r[6], r[9]

		var source uint64
		switch s_ {
		case "Vendor-Kaspersky":
			source = blacklistEntities.SourceKaspersky
		case "Vendor-DRWEB":
			source = blacklistEntities.SourceDrWeb
		case "FinCERT":
			source = blacklistEntities.SourceFinCERT
		default:
			source = blacklistEntities.SourceUnknown
		}

		comment := strings.Trim(c, "\"")

		switch t {
		case "Domain":
			domainMap[v] = &blacklistEntities.BlacklistedDomain{
				URN:         v,
				Description: comment,
				SourceID:    source,
			}
		case "IP-addres":
			ip := pgtype.Inet{}
			err := ip.Set(v)
			if err != nil {
				errors_ = append(errors_, err)
				continue
			}

			ipMap[ip.IPNet.String()] = &blacklistEntities.BlacklistedIP{
				IPAddress:   ip,
				Description: comment,
				SourceID:    source,
			}
		case "URL":
			urlMap[v] = &blacklistEntities.BlacklistedURL{
				URL:         v,
				Description: comment,
				SourceID:    source,
			}
		}
	}

	// async saving of all host types
	var rowsTotal int64 = 0
	wg := sync.WaitGroup{}
	wg.Add(3)

	go func() {
		var ips = make([]blacklistEntities.BlacklistedIP, 0, len(ipMap))
		for _, v := range ipMap {
			ips = append(ips, *v)
		}

		rows, err := s.SaveIPs(ips)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var urls = make([]blacklistEntities.BlacklistedURL, 0, len(urlMap))
		for _, v := range urlMap {
			urls = append(urls, *v)
		}

		rows, err := s.SaveURLs(urls)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	go func() {
		var domains = make([]blacklistEntities.BlacklistedDomain, 0, len(domainMap))
		for _, v := range domainMap {
			domains = append(domains, *v)
		}

		rows, err := s.SaveDomains(domains)
		if err != nil {
			errors_ = append(errors_, err)
		}

		rowsTotal += rows
		wg.Done()
	}()

	wg.Wait()

	return rowsTotal, errors_
}

func (s *BlackListsServiceImpl) ExportToJSON(filter blacklistEntities.BlacklistExportFilter) ([]byte, error) {
	hosts, err := s.repo.SelectHostsUnionByFilter(blacklistEntities.BlacklistSearchFilter{
		SourceIDs:     filter.SourceIDs,
		IsActive:      filter.IsActive,
		CreatedAfter:  filter.CreatedAfter,
		CreatedBefore: filter.CreatedBefore,
	})
	if err != nil {
		return nil, err
	}

	bytes_, err := json.Marshal(hosts)
	if err != nil {
		return nil, err
	}

	return bytes_, nil
}

func (s *BlackListsServiceImpl) ExportToCSV(filter blacklistEntities.BlacklistExportFilter) ([]byte, error) {
	hosts, err := s.repo.SelectHostsUnionByFilter(blacklistEntities.BlacklistSearchFilter{
		SourceIDs:     filter.SourceIDs,
		IsActive:      filter.IsActive,
		CreatedAfter:  filter.CreatedAfter,
		CreatedBefore: filter.CreatedBefore,
	})

	if err != nil {
		return nil, err
	}

	var lines [][]string

	lines = append(lines, []string{"UUID", "Identity", "Source", "CreatedAt", "UpdatedAt"})

	for _, v := range hosts {
		lines = append(lines, []string{fmt.Sprintf("%x", v.UUID.Bytes), v.Host, v.Source.Name, v.CreatedAt.Format("02.01.2006"), v.UpdatedAt.Format("02.01.2006")})
	}

	var buf bytes.Buffer

	w := csv.NewWriter(&buf)
	err = w.WriteAll(lines)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *BlackListsServiceImpl) RetrieveTotalStatistics() (int64, int64, int64) {
	return s.repo.CountStatistics()
}

func (s *BlackListsServiceImpl) RetrieveByDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error) {
	return s.repo.SelectByDateStatistics(startDate, endDate)
}

type BlacklistedBundle struct {
	IPs     []blacklistEntities.BlacklistedIP     `json:"blacklisted_ip_addresses"`
	Domains []blacklistEntities.BlacklistedDomain `json:"blacklisted_domains"`
	URLs    []blacklistEntities.BlacklistedURL    `json:"blacklisted_urls"`
}

func (s *BlackListsServiceImpl) RetrieveAllSources() ([]blacklistEntities.BlacklistSource, error) {
	return s.repo.SelectAllSources()
}
