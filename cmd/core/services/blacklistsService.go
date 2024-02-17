package services

import (
	"bytes"
	"crypto/md5"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"domain_threat_intelligence_api/cmd/core/entities/serviceDeskEntities"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

type BlackListsServiceImpl struct {
	repo core.IBlacklistsRepo
	desk core.IServiceDeskService
}

func NewBlackListsServiceImpl(repo core.IBlacklistsRepo, desk core.IServiceDeskService) *BlackListsServiceImpl {
	return &BlackListsServiceImpl{repo: repo, desk: desk}
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

func (s *BlackListsServiceImpl) RetrieveEmailsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedEmail, error) {
	return s.repo.SelectEmailsByFilter(filter)
}

func (s *BlackListsServiceImpl) SaveEmails(emails []blacklistEntities.BlacklistedEmail) (int64, error) {
	return s.repo.SaveEmails(emails)
}

func (s *BlackListsServiceImpl) DeleteEmail(uuid pgtype.UUID) (int64, error) {
	return s.repo.DeleteEmail(uuid)
}

func (s *BlackListsServiceImpl) SaveImportEvent(event blacklistEntities.BlacklistImportEvent) (blacklistEntities.BlacklistImportEvent, error) {
	return s.repo.SaveImportEvent(event)
}

func (s *BlackListsServiceImpl) RetrieveImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error) {
	return s.repo.SelectImportEventsByFilter(filter)
}

func (s *BlackListsServiceImpl) RetrieveImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error) {
	return s.repo.SelectImportEvent(id)
}

func (s *BlackListsServiceImpl) DeleteImportEvent(id uint64) (int64, error) {
	return s.repo.DeleteImportEvent(id)
}

func (s *BlackListsServiceImpl) ImportFromSTIX2(bundles []blacklistEntities.STIX2Bundle, extractAll bool) (blacklistEntities.BlacklistImportEvent, error) {
	var ipMap = make(map[string]*blacklistEntities.BlacklistedIP)
	var domainMap = make(map[string]*blacklistEntities.BlacklistedDomain)
	var urlMap = make(map[string]*blacklistEntities.BlacklistedURL)
	var emailMap = make(map[string]*blacklistEntities.BlacklistedEmail)

	var summary = blacklistEntities.BlacklistImportEventSummary{}
	event, err := s.SaveImportEvent(blacklistEntities.BlacklistImportEvent{
		Type:       "stix",
		IsComplete: false,
		CreatedAt:  time.Now(),
	})

	if err != nil {
		return blacklistEntities.BlacklistImportEvent{}, err
	} else if event.ID == 0 {
		return blacklistEntities.BlacklistImportEvent{}, errors.New("import event was not created")
	}

	for bIndex, b := range bundles {
		for iIndex, object := range b.Objects {
			if object.Type != "indicator" { // skip all other object types
				summary.Skipped++
				continue
			}

			i, d, u, e, err := object.ToBlacklisted(extractAll)
			if err != nil {
				slog.Error(fmt.Sprintf("error in bundle #%d, value #%d; error: %s", bIndex, iIndex, err.Error()))
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

			if e != nil {
				emailMap[e.Email] = e
			}
		}
	}

	// async saving of all host types
	// 1. insert all imported records with clause
	wg := sync.WaitGroup{}
	wg.Add(4)

	go func() {
		var ips = make([]blacklistEntities.BlacklistedIP, 0, len(ipMap))
		for _, v := range ipMap {
			v.ImportEventID = &event.ID
			ips = append(ips, *v)
		}

		rows, err := s.SaveIPs(ips)
		if err != nil {
			slog.Warn("failed to save IP addresses: " + err.Error())
			summary.Errored += len(ips)
		} else {
			summary.Imported.IPs += rows
		}

		wg.Done()
	}()

	go func() {
		var urls = make([]blacklistEntities.BlacklistedURL, 0, len(urlMap))
		for _, v := range urlMap {
			v.ImportEventID = &event.ID
			urls = append(urls, *v)
		}

		rows, err := s.SaveURLs(urls)
		if err != nil {
			slog.Warn("failed to save URLs: " + err.Error())
			summary.Errored += len(urls)
		} else {
			summary.Imported.URLs += rows
		}

		wg.Done()
	}()

	go func() {
		var domains = make([]blacklistEntities.BlacklistedDomain, 0, len(domainMap))
		for _, v := range domainMap {
			v.ImportEventID = &event.ID
			domains = append(domains, *v)
		}

		rows, err := s.SaveDomains(domains)
		if err != nil {
			slog.Warn("failed to save domains: " + err.Error())
			summary.Errored += len(domains)
		} else {
			summary.Imported.Domains += rows
		}

		wg.Done()
	}()

	go func() {
		var emails = make([]blacklistEntities.BlacklistedEmail, 0, len(emailMap))
		for _, v := range emailMap {
			v.ImportEventID = &event.ID
			emails = append(emails, *v)
		}

		rows, err := s.SaveEmails(emails)
		if err != nil {
			slog.Warn("failed to save emails: " + err.Error())
			summary.Errored += len(emails)
		} else {
			summary.Imported.Emails += rows
		}

		wg.Done()
	}()

	wg.Wait()

	// 2. select all inserted records with event ID
	summary.Imported.Total = summary.Imported.IPs + summary.Imported.Domains + summary.Imported.URLs + summary.Imported.Emails
	hosts, err := s.RetrieveHostsByFilter(blacklistEntities.BlacklistSearchFilter{
		Limit:         int(summary.Imported.Total),
		ImportEventID: event.ID,
	})

	if err != nil {
		return blacklistEntities.BlacklistImportEvent{}, nil
	}

	// count by type
	for _, h := range hosts {
		switch h.Type {
		case "ip":
			summary.New.IPs++
		case "url":
			summary.New.URLs++
		case "domain":
			summary.New.Domains++
		case "email":
			summary.New.Emails++
		}
	}

	summary.New.Total = summary.New.IPs + summary.New.Domains + summary.New.URLs + summary.New.Emails

	// saving import event updates
	event.Summary = datatypes.NewJSONType(summary)
	event.IsComplete = true

	return s.SaveImportEvent(event)
}

func (s *BlackListsServiceImpl) ImportFromCSV(data [][]string, discoveredAt time.Time, extractAll bool) (blacklistEntities.BlacklistImportEvent, error) {
	var ipMap = make(map[string]*blacklistEntities.BlacklistedIP)
	var domainMap = make(map[string]*blacklistEntities.BlacklistedDomain)
	var urlMap = make(map[string]*blacklistEntities.BlacklistedURL)
	var emailMap = make(map[string]*blacklistEntities.BlacklistedEmail)

	var summary = blacklistEntities.BlacklistImportEventSummary{}
	event, err := s.SaveImportEvent(blacklistEntities.BlacklistImportEvent{
		Type:       "csv",
		IsComplete: false,
		CreatedAt:  time.Now(),
	})

	if err != nil {
		return blacklistEntities.BlacklistImportEvent{}, err
	} else if event.ID == 0 {
		return blacklistEntities.BlacklistImportEvent{}, errors.New("import event was not created")
	}

	var headerIndexes = struct {
		TypeIOC   int
		Value     int
		Source    int
		FirstSeen int
		Comment   int
	}{
		TypeIOC:   slices.Index(data[0], "Type_IOC"),
		Value:     slices.Index(data[0], "Value"),
		Source:    slices.Index(data[0], "Source"),
		FirstSeen: slices.Index(data[0], "First Seen"),
		Comment:   slices.Index(data[0], "Comment"),
	}

	// read all lines, remove header
	for _, row := range data[1:] {
		var IoCType string
		if headerIndexes.TypeIOC != -1 {
			IoCType = strings.ToLower(row[headerIndexes.TypeIOC])
		} else {
			slog.Warn("value not defined")
			continue
		}

		var value string
		if headerIndexes.Value != -1 {
			value = row[headerIndexes.Value]
		} else {
			slog.Warn("value not defined")
			continue
		}

		var source uint64
		if headerIndexes.Source != -1 {
			switch row[headerIndexes.Source] {
			case "Vendor-Kaspersky":
				source = blacklistEntities.SourceKaspersky
			case "Vendor-DRWEB":
				source = blacklistEntities.SourceDrWeb
			case "FinCERT", "Vendor":
				source = blacklistEntities.SourceFinCERT
			default:
				source = blacklistEntities.SourceUnknown
			}
		} else {
			source = blacklistEntities.SourceUnknown
		}

		var comment string
		if headerIndexes.Comment != -1 {
			comment = strings.Trim(row[headerIndexes.Comment], "\"")
		}

		var discoveryDate time.Time
		if headerIndexes.FirstSeen != -1 {
			var err error

			discoveryDate, err = time.Parse("02.01.2006", row[headerIndexes.FirstSeen])
			if err != nil {
				discoveryDate = discoveredAt
			}
		} else {
			discoveryDate = discoveredAt
		}

		switch IoCType {
		case "domain":
			domainMap[value] = &blacklistEntities.BlacklistedDomain{
				URN:           value,
				Description:   comment,
				SourceID:      source,
				ImportEventID: &event.ID,
				DiscoveredAt:  discoveryDate,
			}
		case "email":
			emailMap[value] = &blacklistEntities.BlacklistedEmail{
				Email:         value,
				Description:   comment,
				SourceID:      source,
				ImportEventID: &event.ID,
				DiscoveredAt:  discoveryDate,
			}

			if !extractAll {
				break
			}

			p := strings.Split("@", value)
			if len(p) > 1 {
				domain := p[len(p)]
				if len(domain) > 0 {
					domainMap[domain] = &blacklistEntities.BlacklistedDomain{
						URN:           domain,
						Description:   comment,
						SourceID:      source,
						ImportEventID: &event.ID,
						DiscoveredAt:  discoveryDate,
					}
				}
			}
		case "url":
			urlMap[value] = &blacklistEntities.BlacklistedURL{
				URL:           value,
				Description:   comment,
				SourceID:      source,
				ImportEventID: &event.ID,
				DiscoveredAt:  discoveryDate,
			}

			if !extractAll {
				break
			}

			// find IP address in URL or extract domain name
			p := blacklistEntities.ExtractIPFromPattern(value)
			if len(p) > 0 {
				ip := pgtype.Inet{}
				err = ip.Set(p)
				if err == nil {
					ipMap[ip.IPNet.String()] = &blacklistEntities.BlacklistedIP{
						IPAddress:     ip,
						Description:   comment,
						SourceID:      source,
						ImportEventID: &event.ID,
						DiscoveredAt:  discoveryDate,
					}
				}
			} else {
				d := value
				if !strings.Contains(value, "http") {
					d = "//" + value
				}

				domain, err := url.Parse(d)
				if err == nil {
					domainMap[domain.Hostname()] = &blacklistEntities.BlacklistedDomain{
						URN:           value,
						Description:   comment,
						SourceID:      source,
						ImportEventID: &event.ID,
						DiscoveredAt:  discoveryDate,
					}
				}
			}
		case "ip", "ip-addres", "ip-address":
			ip := pgtype.Inet{}
			err := ip.Set(value)
			if err != nil {
				continue
			}

			ipMap[ip.IPNet.String()] = &blacklistEntities.BlacklistedIP{
				IPAddress:     ip,
				Description:   comment,
				SourceID:      source,
				ImportEventID: &event.ID,
				DiscoveredAt:  discoveryDate,
			}
		default:
			summary.Skipped += 1 // sha values skipped
		}
	}

	// async saving of all host types
	wg := sync.WaitGroup{}
	wg.Add(4)

	go func() {
		var ips = make([]blacklistEntities.BlacklistedIP, 0, len(ipMap))
		for _, v := range ipMap {
			ips = append(ips, *v)
		}

		rows, err := s.SaveIPs(ips)
		if err != nil {
			slog.Warn("failed to save IP addresses: " + err.Error())
			summary.Errored += len(ips)
		} else {
			summary.Imported.IPs += rows
		}

		wg.Done()
	}()

	go func() {
		var urls = make([]blacklistEntities.BlacklistedURL, 0, len(urlMap))
		for _, v := range urlMap {
			urls = append(urls, *v)
		}

		rows, err := s.SaveURLs(urls)
		if err != nil {
			slog.Warn("failed to save URLs: " + err.Error())
			summary.Errored += len(urls)
		} else {
			summary.Imported.URLs += rows
		}

		wg.Done()
	}()

	go func() {
		var domains = make([]blacklistEntities.BlacklistedDomain, 0, len(domainMap))
		for _, v := range domainMap {
			domains = append(domains, *v)
		}

		rows, err := s.SaveDomains(domains)
		if err != nil {
			slog.Warn("failed to save domains: " + err.Error())
			summary.Errored += len(domains)
		} else {
			summary.Imported.Domains += rows
		}

		wg.Done()
	}()

	go func() {
		var emails = make([]blacklistEntities.BlacklistedEmail, 0, len(emailMap))
		for _, v := range emailMap {
			emails = append(emails, *v)
		}

		rows, err := s.SaveEmails(emails)
		if err != nil {
			slog.Warn("failed to save emails: " + err.Error())
			summary.Errored += len(emails)
		} else {
			summary.Imported.Emails += rows
		}

		wg.Done()
	}()

	wg.Wait()

	// saving import event updates
	summary.Imported.Total = summary.Imported.IPs + summary.Imported.Domains + summary.Imported.URLs + summary.Imported.Emails

	event.Summary = datatypes.NewJSONType(summary)
	event.IsComplete = true

	return s.SaveImportEvent(event)
}

func (s *BlackListsServiceImpl) ExportToJSON(filter blacklistEntities.BlacklistSearchFilter) ([]byte, error) {
	hosts, err := s.repo.SelectHostsUnionByFilter(filter)
	if err != nil {
		return nil, err
	}

	bytes_, err := json.Marshal(hosts)
	if err != nil {
		return nil, err
	}

	return bytes_, nil
}

func (s *BlackListsServiceImpl) ExportToCSV(filter blacklistEntities.BlacklistSearchFilter) ([]byte, error) {
	hosts, err := s.repo.SelectHostsUnionByFilter(filter)

	if err != nil {
		return nil, err
	}

	var lines [][]string

	lines = append(lines, []string{"UUID", "Type", "Identity", "Source", "CreatedAt", "UpdatedAt"})

	for _, v := range hosts {
		lines = append(lines, []string{fmt.Sprintf("%x", v.UUID.Bytes), v.Type, v.Host, v.Source.Name, v.CreatedAt.Format("02.01.2006"), v.UpdatedAt.Format("02.01.2006")})
	}

	var buf bytes.Buffer

	w := csv.NewWriter(&buf)
	err = w.WriteAll(lines)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *BlackListsServiceImpl) ExportToNaumen(filter blacklistEntities.BlacklistSearchFilter) (serviceDeskEntities.ServiceDeskTicket, error) {
	if !s.desk.IsAvailable() {
		return serviceDeskEntities.ServiceDeskTicket{}, errors.New("service desk not configured")
	}

	hosts, err := s.repo.SelectHostsUnionByFilter(filter)
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	ticket, err := s.desk.SendBlacklistedHosts(hosts)
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	return ticket, nil
}

func (s *BlackListsServiceImpl) RetrieveTotalStatistics() (int64, int64, int64, int64) {
	return s.repo.CountStatistics()
}

func (s *BlackListsServiceImpl) RetrieveByCreationDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error) {
	return s.repo.SelectByCreationDateStatistics(startDate, endDate)
}

func (s *BlackListsServiceImpl) RetrieveByDiscoveryDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error) {
	return s.repo.SelectByDiscoveryDateStatistics(startDate, endDate)
}

type BlacklistedBundle struct {
	IPs     []blacklistEntities.BlacklistedIP     `json:"blacklisted_ip_addresses"`
	Domains []blacklistEntities.BlacklistedDomain `json:"blacklisted_domains"`
	URLs    []blacklistEntities.BlacklistedURL    `json:"blacklisted_urls"`
}

func (s *BlackListsServiceImpl) RetrieveAllSources() ([]blacklistEntities.BlacklistSource, error) {
	return s.repo.SelectAllSources()
}
