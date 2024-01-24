package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities"
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

func (r *BlacklistsRepoImpl) SelectURLsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedURL, error) {
	query := r.Model(&entities.BlacklistedURL{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Unscoped()
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("URL LIKE ?", "%"+filter.SearchString+"%")
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []entities.BlacklistedURL
	err := query.Preload("Source").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	return result, err
}

func (r *BlacklistsRepoImpl) SaveURLs(urls []entities.BlacklistedURL) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "md5"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&urls, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteURL(uuid pgtype.UUID) (int64, error) {
	query := r.Delete(&entities.BlacklistedURL{
		UUID: uuid,
	})

	return query.RowsAffected, query.Error
}

func NewBlacklistsRepoImpl(DB *gorm.DB) *BlacklistsRepoImpl {
	return &BlacklistsRepoImpl{DB: DB}
}

func (r *BlacklistsRepoImpl) SelectIPsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedIP, error) {
	query := r.Model(&entities.BlacklistedIP{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Unscoped()
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("ip_address <<= ?", filter.SearchString)
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []entities.BlacklistedIP
	err := query.Preload("Source").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	return result, err
}

// SaveIPs saves ip records to database. If ip with specific source not presented, creates one.
// If defined combination already in database, updates it and makes it active.
func (r *BlacklistsRepoImpl) SaveIPs(ips []entities.BlacklistedIP) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip_address"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&ips, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteIP(uuid pgtype.UUID) (int64, error) {
	query := r.Delete(&entities.BlacklistedIP{
		UUID: uuid,
	})

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) SelectDomainsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedDomain, error) {
	query := r.Model(&entities.BlacklistedDomain{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Unscoped()
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("URN LIKE ?", "%"+filter.SearchString+"%")
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []entities.BlacklistedDomain
	err := query.Preload("Source").Offset(filter.Offset).Order("created_at DESC, updated_at DESC, UUID DESC").Find(&result).Error

	return result, err
}

// SaveDomains saves domain records to database. If domain with specific source not presented, creates one.
// If defined combination already in database, updates it and makes it active.
func (r *BlacklistsRepoImpl) SaveDomains(domains []entities.BlacklistedDomain) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "urn"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&domains, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteDomain(uuid pgtype.UUID) (int64, error) {
	query := r.Delete(&entities.BlacklistedDomain{
		UUID: uuid,
	})

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) CountStatistics() (int64, int64, int64) {
	var ipCount, urlCount, domainCount int64

	r.Model(&entities.BlacklistedIP{}).Count(&ipCount)
	r.Model(&entities.BlacklistedURL{}).Count(&urlCount)
	r.Model(&entities.BlacklistedDomain{}).Count(&domainCount)

	return ipCount, urlCount, domainCount
}

func (r *BlacklistsRepoImpl) SelectAllSources() ([]entities.BlacklistSource, error) {
	var sources []entities.BlacklistSource

	err := r.Find(&sources).Error
	if err != nil {
		return nil, err
	}

	return sources, err
}

func (r *BlacklistsRepoImpl) SelectHostsUnionByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedHost, error) {
	var hosts []entities.BlacklistedHost
	var err error

	ipQuery := r.Model(&entities.BlacklistedIP{}).Select("uuid, abbrev(ip_address) AS host, 'ip' AS type, description, source_id, created_at, updated_at, deleted_at")
	urlQuery := r.Model(&entities.BlacklistedURL{}).Select("uuid, url AS host, 'url' AS type, description, source_id, created_at, updated_at, deleted_at")
	domainQuery := r.Model(&entities.BlacklistedDomain{}).Select("uuid, urn AS host, 'domain' AS type, description, source_id, created_at, updated_at, deleted_at")

	if filter.IsActive != nil && *filter.IsActive == false {
		ipQuery = ipQuery.Unscoped()
		urlQuery = urlQuery.Unscoped()
		domainQuery = domainQuery.Unscoped()
	}

	if filter.CreatedAfter != nil {
		ipQuery = ipQuery.Where("created_at > ?", filter.CreatedAfter)
		urlQuery = urlQuery.Where("created_at > ?", filter.CreatedAfter)
		domainQuery = domainQuery.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		ipQuery = ipQuery.Where("created_at < ?", filter.CreatedBefore)
		urlQuery = urlQuery.Where("created_at < ?", filter.CreatedBefore)
		domainQuery = domainQuery.Where("created_at < ?", filter.CreatedBefore)
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
	}

	if len(filter.SourceIDs) > 0 {
		ipQuery = ipQuery.Where("source_id IN ?", filter.SourceIDs)
		urlQuery = urlQuery.Where("source_id IN ?", filter.SourceIDs)
		domainQuery = domainQuery.Where("source_id IN ?", filter.SourceIDs)
	}

	var query = "? UNION ? UNION ? ORDER BY created_at DESC, updated_at DESC, UUID DESC OFFSET ?"

	if filter.Limit != 0 {
		query += " LIMIT ?"
		err = r.Raw(query,
			ipQuery,
			urlQuery,
			domainQuery,
			filter.Offset,
			filter.Limit,
		).Scan(&hosts).Error
	} else {
		err = r.Raw(query,
			ipQuery,
			urlQuery,
			domainQuery,
			filter.Offset,
		).Scan(&hosts).Error
	}

	if err != nil {
		return nil, err
	}

	//query := r.Raw("SELECT uuid, abbrev(ip_address) AS host, 'ip' AS type, description, source_id, created_at, updated_at, deleted_at FROM blacklisted_ips "+
	//	"UNION "+
	//	"SELECT uuid, url AS host, 'url' AS type, description, source_id, created_at, updated_at, deleted_at FROM blacklisted_urls "+
	//	"UNION "+
	//	"SELECT uuid, urn AS host, 'domain' AS type, description, source_id, created_at, updated_at, deleted_at FROM blacklisted_domains "+
	//	"ORDER BY created_at DESC, updated_at DESC "+
	//	"LIMIT ? OFFSET ?;", filter.Limit, filter.Offset).
	//	Scan(&hosts)

	for i, h := range hosts {
		hosts[i].Status = h.GetStatus()

		switch h.SourceID {
		case entities.SourceManual:
			hosts[i].Source = &entities.DefaultSources[0]
		case entities.SourceFinCERT:
			hosts[i].Source = &entities.DefaultSources[1]
		case entities.SourceKaspersky:
			hosts[i].Source = &entities.DefaultSources[2]
		case entities.SourceDrWeb:
			hosts[i].Source = &entities.DefaultSources[3]
		case entities.SourceUnknown:
			hosts[i].Source = &entities.DefaultSources[4]
		}

	}

	return hosts, err
}

func (r *BlacklistsRepoImpl) SelectByDateStatistics(startDate, endDate time.Time) ([]entities.BlacklistedByDate, error) {
	var byDate []entities.BlacklistedByDate

	ipQuery := r.Model(&entities.BlacklistedIP{}).Select("date(created_at) AS date, count(*), 'ip' AS type").Group("date(created_at)")
	urlQuery := r.Model(&entities.BlacklistedURL{}).Select("date(created_at) AS date, count(*), 'url' AS type").Group("date(created_at)")
	domainQuery := r.Model(&entities.BlacklistedDomain{}).Select("date(created_at) AS date, count(*), 'domain' AS type").Group("date(created_at)")

	if !startDate.IsZero() {
		ipQuery = ipQuery.Where("created_at > ?", startDate)
		urlQuery = urlQuery.Where("created_at > ?", startDate)
		domainQuery = domainQuery.Where("created_at > ?", startDate)
	}

	if !endDate.IsZero() {
		ipQuery = ipQuery.Where("created_at < ?", endDate)
		urlQuery = urlQuery.Where("created_at < ?", endDate)
		domainQuery = domainQuery.Where("created_at < ?", endDate)
	}

	err := r.Raw("? UNION ? UNION ? ORDER BY date DESC",
		ipQuery,
		urlQuery,
		domainQuery,
	).Scan(&byDate).Error

	if err != nil {
		return nil, err
	}

	return byDate, nil
}
