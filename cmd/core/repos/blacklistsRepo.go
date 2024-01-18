package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"time"
)

type BlacklistsRepoImpl struct {
	*gorm.DB
}

func (r *BlacklistsRepoImpl) SelectURLsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedURL, error) {
	query := r.Model(&entities.BlacklistedURL{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Where("deleted_at IS NULL")
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

	var result []entities.BlacklistedURL
	err := query.Preload("Source").Offset(filter.Offset).Find(&result).Error

	return result, err
}

func (r *BlacklistsRepoImpl) SaveURLs(urls []entities.BlacklistedURL) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "md5"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).CreateInBatches(&urls, 100)

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) DeleteURL(id uint64) (int64, error) {
	query := r.Delete(&entities.BlacklistedURL{
		Model: gorm.Model{
			ID: uint(id),
		},
	})

	return query.RowsAffected, query.Error
}

func NewBlacklistsRepoImpl(DB *gorm.DB) *BlacklistsRepoImpl {
	return &BlacklistsRepoImpl{DB: DB}
}

func (r *BlacklistsRepoImpl) SelectIPsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedIP, error) {
	query := r.Model(&entities.BlacklistedIP{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Where("deleted_at IS NULL")
	}

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if len(filter.SearchString) > 0 {
		query = query.Where("ip_address << ?", filter.SearchString)
	}

	if len(filter.SourceIDs) > 0 {
		query = query.Where("source_id IN ?", filter.SourceIDs)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []entities.BlacklistedIP
	err := query.Preload("Source").Offset(filter.Offset).Find(&result).Error

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

func (r *BlacklistsRepoImpl) DeleteIP(id uint64) (int64, error) {
	query := r.Delete(&entities.BlacklistedIP{
		Model: gorm.Model{
			ID: uint(id),
		},
	})

	return query.RowsAffected, query.Error
}

func (r *BlacklistsRepoImpl) SelectDomainsByFilter(filter entities.BlacklistSearchFilter) ([]entities.BlacklistedDomain, error) {
	query := r.Model(&entities.BlacklistedDomain{})

	if filter.IsActive != nil && *filter.IsActive == true {
		query = query.Where("deleted_at IS NULL")
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
	err := query.Preload("Source").Offset(filter.Offset).Find(&result).Error

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

func (r *BlacklistsRepoImpl) DeleteDomain(id uint64) (int64, error) {
	query := r.Delete(&entities.BlacklistedDomain{
		Model: gorm.Model{
			ID: uint(id),
		},
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
