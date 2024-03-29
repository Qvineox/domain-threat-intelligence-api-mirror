package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities/blacklistEntities"
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"log/slog"
	"net"
	"time"
)

type BlacklistsRepoImpl struct {
	*gorm.DB
}

func (r *BlacklistsRepoImpl) SelectURLsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedURL, error) {
	query := r.Model(&blacklistEntities.BlacklistedURL{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Unscoped()
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if filter.DiscoveredAfter != nil {
		query = query.Where("discovered_at > ?", filter.DiscoveredAfter)
	}

	if filter.DiscoveredBefore != nil {
		query = query.Where("discovered_at < ?", filter.DiscoveredBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("URL LIKE ?", "%"+filter.SearchString+"%")
	}

	if filter.ImportEventID > 0 {
		query = query.Where("import_event_id = ?", filter.ImportEventID)
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []blacklistEntities.BlacklistedURL
	err := query.Preload("Source").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	return result, err
}

func (r *BlacklistsRepoImpl) SaveURLs(urls []blacklistEntities.BlacklistedURL) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "md5"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&urls, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteURL(uuid pgtype.UUID) (int64, error) {
	query := r.Delete(&blacklistEntities.BlacklistedURL{
		UUID: uuid,
	})

	return query.RowsAffected, query.Error
}

func NewBlacklistsRepoImpl(DB *gorm.DB) *BlacklistsRepoImpl {
	return &BlacklistsRepoImpl{DB: DB}
}

func (r *BlacklistsRepoImpl) SelectIPsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedIP, error) {
	query := r.Model(&blacklistEntities.BlacklistedIP{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Unscoped()
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if filter.DiscoveredAfter != nil {
		query = query.Where("discovered_at > ?", filter.DiscoveredAfter)
	}

	if filter.DiscoveredBefore != nil {
		query = query.Where("discovered_at < ?", filter.DiscoveredBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("ip_address <<= ?", filter.SearchString)
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.ImportEventID > 0 {
		query = query.Where("import_event_id = ?", filter.ImportEventID)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []blacklistEntities.BlacklistedIP
	err := query.Preload("Source").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	return result, err
}

// SaveIPs saves ip records to database. If ip with specific source not presented, creates one.
// If defined combination already in database, updates it and makes it active.
func (r *BlacklistsRepoImpl) SaveIPs(ips []blacklistEntities.BlacklistedIP) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip_address"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&ips, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteIP(uuid pgtype.UUID) (int64, error) {
	query := r.Delete(&blacklistEntities.BlacklistedIP{
		UUID: uuid,
	})

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) SelectDomainsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedDomain, error) {
	query := r.Model(&blacklistEntities.BlacklistedDomain{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Unscoped()
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if filter.DiscoveredAfter != nil {
		query = query.Where("discovered_at > ?", filter.DiscoveredAfter)
	}

	if filter.DiscoveredBefore != nil {
		query = query.Where("discovered_at < ?", filter.DiscoveredBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("URN LIKE ?", "%"+filter.SearchString+"%")
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.ImportEventID > 0 {
		query = query.Where("import_event_id = ?", filter.ImportEventID)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []blacklistEntities.BlacklistedDomain
	err := query.Preload("Source").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	return result, err
}

// SaveDomains saves domain records to database. If domain with specific source not presented, creates one.
// If defined combination already in database, updates it and makes it active.
func (r *BlacklistsRepoImpl) SaveDomains(domains []blacklistEntities.BlacklistedDomain) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "urn"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&domains, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteDomain(uuid pgtype.UUID) (int64, error) {
	query := r.Delete(&blacklistEntities.BlacklistedDomain{
		UUID: uuid,
	})

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) SelectEmailsByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedEmail, error) {
	query := r.Model(&blacklistEntities.BlacklistedEmail{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Unscoped()
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if filter.DiscoveredAfter != nil {
		query = query.Where("discovered_at > ?", filter.DiscoveredAfter)
	}

	if filter.DiscoveredBefore != nil {
		query = query.Where("discovered_at < ?", filter.DiscoveredBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("URN LIKE ?", "%"+filter.SearchString+"%")
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.ImportEventID > 0 {
		query = query.Where("import_event_id = ?", filter.ImportEventID)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []blacklistEntities.BlacklistedEmail
	err := query.Preload("Source").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	return result, err
}

func (r *BlacklistsRepoImpl) SaveEmails(emails []blacklistEntities.BlacklistedEmail) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "email"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&emails, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteEmail(uuid pgtype.UUID) (int64, error) {
	query := r.Delete(&blacklistEntities.BlacklistedEmail{
		UUID: uuid,
	})

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) SaveImportEvent(event blacklistEntities.BlacklistImportEvent) (blacklistEntities.BlacklistImportEvent, error) {
	err := r.Save(&event).Error
	if err != nil {
		return blacklistEntities.BlacklistImportEvent{}, err
	}

	return event, nil
}

func (r *BlacklistsRepoImpl) SelectImportEventsByFilter(filter blacklistEntities.BlacklistImportEventFilter) ([]blacklistEntities.BlacklistImportEvent, error) {
	query := r.Model(&blacklistEntities.BlacklistImportEvent{})

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if len(filter.Type) > 0 {
		query = query.Where("type = ?", filter.Type)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []blacklistEntities.BlacklistImportEvent
	err := query.Offset(filter.Offset).Order("created_at DESC, ID DESC").Find(&result).Error

	return result, err
}

func (r *BlacklistsRepoImpl) SelectImportEvent(id uint64) (blacklistEntities.BlacklistImportEvent, error) {
	event := blacklistEntities.BlacklistImportEvent{}

	err := r.Find(&event, id).Error
	if err != nil {
		return blacklistEntities.BlacklistImportEvent{}, err
	}

	return event, nil
}

func (r *BlacklistsRepoImpl) DeleteImportEvent(id uint64) (int64, error) {
	query := r.Delete(&blacklistEntities.BlacklistImportEvent{
		ID: id,
	})

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) CountStatistics() (int64, int64, int64, int64) {
	var ipCount, urlCount, domainCount, emailCount int64

	r.Model(&blacklistEntities.BlacklistedIP{}).Count(&ipCount)
	r.Model(&blacklistEntities.BlacklistedURL{}).Count(&urlCount)
	r.Model(&blacklistEntities.BlacklistedDomain{}).Count(&domainCount)
	r.Model(&blacklistEntities.BlacklistedEmail{}).Count(&emailCount)

	return ipCount, urlCount, domainCount, emailCount
}

func (r *BlacklistsRepoImpl) SelectAllSources() ([]blacklistEntities.BlacklistSource, error) {
	var sources []blacklistEntities.BlacklistSource

	err := r.Find(&sources).Error
	if err != nil {
		return nil, err
	}

	return sources, err
}

func (r *BlacklistsRepoImpl) SelectHostsUnionByFilter(filter blacklistEntities.BlacklistSearchFilter) ([]blacklistEntities.BlacklistedHost, error) {
	var hosts []blacklistEntities.BlacklistedHost
	var err error

	ipQuery := r.Model(&blacklistEntities.BlacklistedIP{}).Select("uuid, abbrev(ip_address) AS host, 'ip' AS type, description, source_id, import_event_id, discovered_at, created_at, updated_at, deleted_at")
	urlQuery := r.Model(&blacklistEntities.BlacklistedURL{}).Select("uuid, url AS host, 'url' AS type, description, source_id, import_event_id, discovered_at, created_at, updated_at, deleted_at")
	domainQuery := r.Model(&blacklistEntities.BlacklistedDomain{}).Select("uuid, urn AS host, 'domain' AS type, description, source_id, import_event_id, discovered_at, created_at, updated_at, deleted_at")
	emailQuery := r.Model(&blacklistEntities.BlacklistedEmail{}).Select("uuid, email AS host, 'email' AS type, description, source_id, import_event_id, discovered_at, created_at, updated_at, deleted_at")

	if filter.IsActive != nil && *filter.IsActive == false {
		ipQuery = ipQuery.Unscoped()
		urlQuery = urlQuery.Unscoped()
		domainQuery = domainQuery.Unscoped()
		emailQuery = emailQuery.Unscoped()
	}

	if filter.CreatedAfter != nil {
		ipQuery = ipQuery.Where("created_at > ?", filter.CreatedAfter)
		urlQuery = urlQuery.Where("created_at > ?", filter.CreatedAfter)
		domainQuery = domainQuery.Where("created_at > ?", filter.CreatedAfter)
		emailQuery = emailQuery.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		ipQuery = ipQuery.Where("created_at < ?", filter.CreatedBefore)
		urlQuery = urlQuery.Where("created_at < ?", filter.CreatedBefore)
		domainQuery = domainQuery.Where("created_at < ?", filter.CreatedBefore)
		emailQuery = emailQuery.Where("created_at < ?", filter.CreatedBefore)
	}

	if len(filter.SearchString) > 0 {
		var addr string = "0.0.0.0/32"

		// check if search string is IP or IP with mask
		_, _, err := net.ParseCIDR(filter.SearchString)
		ip := net.ParseIP(filter.SearchString)

		if err != nil && ip == nil {
			slog.Warn("failed to parse CIDR in multi-search: " + err.Error())
		} else if err != nil {
			addr = ip.String() + "/32"
		} else {
			addr = filter.SearchString
		}

		ipQuery = ipQuery.Where("ip_address <<= ?", addr)
		urlQuery = urlQuery.Where("url LIKE ?", "%"+filter.SearchString+"%")
		domainQuery = domainQuery.Where("urn LIKE ?", "%"+filter.SearchString+"%")
		emailQuery = emailQuery.Where("email LIKE ?", "%"+filter.SearchString+"%")
	}

	if len(filter.SourceIDs) > 0 {
		ipQuery = ipQuery.Where("source_id IN ?", filter.SourceIDs)
		urlQuery = urlQuery.Where("source_id IN ?", filter.SourceIDs)
		domainQuery = domainQuery.Where("source_id IN ?", filter.SourceIDs)
		emailQuery = emailQuery.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.ImportEventID > 0 {
		ipQuery = ipQuery.Where("import_event_id = ?", filter.ImportEventID)
		urlQuery = urlQuery.Where("import_event_id = ?", filter.ImportEventID)
		domainQuery = domainQuery.Where("import_event_id = ?", filter.ImportEventID)
		emailQuery = emailQuery.Where("import_event_id = ?", filter.ImportEventID)
	}

	var query = "? UNION ? UNION ? UNION ? ORDER BY created_at DESC, updated_at DESC, UUID DESC OFFSET ?"

	if filter.Limit != 0 {
		query += " LIMIT ?"
		err = r.Raw(query,
			ipQuery,
			urlQuery,
			domainQuery,
			emailQuery,
			filter.Offset,
			filter.Limit,
		).Scan(&hosts).Error
	} else {
		err = r.Raw(query,
			ipQuery,
			urlQuery,
			domainQuery,
			emailQuery,
			filter.Offset,
		).Scan(&hosts).Error
	}

	if err != nil {
		return nil, err
	}

	// query := r.Raw("SELECT uuid, abbrev(ip_address) AS host, 'ip' AS type, description, source_id, created_at, updated_at, deleted_at FROM blacklisted_ips "+
	//	"UNION "+
	//	"SELECT uuid, url AS host, 'url' AS type, description, source_id, created_at, updated_at, deleted_at FROM blacklisted_urls "+
	//	"UNION "+
	//	"SELECT uuid, urn AS host, 'domain' AS type, description, source_id, created_at, updated_at, deleted_at FROM blacklisted_domains "+
	//	"ORDER BY created_at DESC, updated_at DESC "+
	//	"LIMIT ? OFFSET ?;", filter.Limit, filter.Offset).
	//	Scan(&hosts)

	now := time.Now()
	threshold := now.Add(-2 * time.Hour)

	for i, h := range hosts {
		hosts[i].Status = blacklistEntities.HostStatusDefault

		if !h.DeletedAt.Time.IsZero() {
			hosts[i].Status = blacklistEntities.HostStatusDeleted
		} else if h.CreatedAt.After(threshold) {
			hosts[i].Status = blacklistEntities.HostStatusNew
		} else if h.UpdatedAt.After(threshold) {
			hosts[i].Status = blacklistEntities.HostStatusUpdated
		}

		switch h.SourceID {
		case blacklistEntities.SourceManual:
			hosts[i].Source = &blacklistEntities.DefaultSources[0]
		case blacklistEntities.SourceFinCERT:
			hosts[i].Source = &blacklistEntities.DefaultSources[1]
		case blacklistEntities.SourceKaspersky:
			hosts[i].Source = &blacklistEntities.DefaultSources[2]
		case blacklistEntities.SourceDrWeb:
			hosts[i].Source = &blacklistEntities.DefaultSources[3]
		case blacklistEntities.SourceUnknown:
			hosts[i].Source = &blacklistEntities.DefaultSources[4]
		}

	}

	return hosts, err
}

func (r *BlacklistsRepoImpl) SelectByCreationDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error) {
	var byDate []blacklistEntities.BlacklistedByDate

	ipQuery := r.Model(&blacklistEntities.BlacklistedIP{}).Select("date(created_at) AS date, count(*), 'ip' AS type").Group("date(created_at)")
	urlQuery := r.Model(&blacklistEntities.BlacklistedURL{}).Select("date(created_at) AS date, count(*), 'url' AS type").Group("date(created_at)")
	domainQuery := r.Model(&blacklistEntities.BlacklistedDomain{}).Select("date(created_at) AS date, count(*), 'domain' AS type").Group("date(created_at)")
	emailQuery := r.Model(&blacklistEntities.BlacklistedDomain{}).Select("date(created_at) AS date, count(*), 'email' AS type").Group("date(created_at)")

	if !startDate.IsZero() {
		ipQuery = ipQuery.Where("created_at > ?", startDate)
		urlQuery = urlQuery.Where("created_at > ?", startDate)
		domainQuery = domainQuery.Where("created_at > ?", startDate)
		emailQuery = emailQuery.Where("created_at > ?", startDate)
	}

	if !endDate.IsZero() {
		ipQuery = ipQuery.Where("created_at < ?", endDate)
		urlQuery = urlQuery.Where("created_at < ?", endDate)
		domainQuery = domainQuery.Where("created_at < ?", endDate)
		emailQuery = emailQuery.Where("created_at < ?", endDate)
	}

	err := r.Raw("? UNION ? UNION ? UNION ? ORDER BY date ASC",
		ipQuery,
		urlQuery,
		domainQuery,
		emailQuery,
	).Scan(&byDate).Error

	if err != nil {
		return nil, err
	}

	return byDate, nil
}

func (r *BlacklistsRepoImpl) SelectByDiscoveryDateStatistics(startDate, endDate time.Time) ([]blacklistEntities.BlacklistedByDate, error) {
	var byDate []blacklistEntities.BlacklistedByDate

	ipQuery := r.Model(&blacklistEntities.BlacklistedIP{}).Select("date(discovered_at) AS date, count(*), 'ip' AS type").Group("date(discovered_at)")
	urlQuery := r.Model(&blacklistEntities.BlacklistedURL{}).Select("date(discovered_at) AS date, count(*), 'url' AS type").Group("date(discovered_at)")
	domainQuery := r.Model(&blacklistEntities.BlacklistedDomain{}).Select("date(discovered_at) AS date, count(*), 'domain' AS type").Group("date(discovered_at)")
	emailQuery := r.Model(&blacklistEntities.BlacklistedDomain{}).Select("date(discovered_at) AS date, count(*), 'email' AS type").Group("date(discovered_at)")

	if !startDate.IsZero() {
		ipQuery = ipQuery.Where("discovered_at > ?", startDate)
		urlQuery = urlQuery.Where("discovered_at > ?", startDate)
		domainQuery = domainQuery.Where("discovered_at > ?", startDate)
		emailQuery = emailQuery.Where("discovered_at > ?", startDate)
	}

	if !endDate.IsZero() {
		ipQuery = ipQuery.Where("discovered_at < ?", endDate)
		urlQuery = urlQuery.Where("discovered_at < ?", endDate)
		domainQuery = domainQuery.Where("discovered_at < ?", endDate)
		emailQuery = emailQuery.Where("discovered_at < ?", endDate)
	}

	err := r.Raw("? UNION ? UNION ? UNION ? ORDER BY date ASC",
		ipQuery,
		urlQuery,
		domainQuery,
		emailQuery,
	).Scan(&byDate).Error

	if err != nil {
		return nil, err
	}

	return byDate, nil
}
