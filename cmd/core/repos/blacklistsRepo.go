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

func NewBlacklistsRepoImpl(DB *gorm.DB) *BlacklistsRepoImpl {
	return &BlacklistsRepoImpl{DB: DB}
}

func (r *BlacklistsRepoImpl) SelectIPsByFilter(filter entities.BlacklistFilter) ([]entities.BlacklistedIP, error) {
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

	var result []entities.BlacklistedIP
	err := query.Limit(filter.Limit).Offset(filter.Offset).Find(&result).Error

	return result, err
}

// SaveIPs saves ip records to database. If ip with specific source not presented, creates one.
// If defined combination already in database, updates it and makes it active.
func (r *BlacklistsRepoImpl) SaveIPs(ips []entities.BlacklistedIP) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "ip_address"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).Save(&ips)

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

func (r *BlacklistsRepoImpl) SelectDomainsByFilter(filter entities.BlacklistFilter) ([]entities.BlacklistedDomain, error) {
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

	var result []entities.BlacklistedDomain
	err := query.Limit(filter.Limit).Offset(filter.Offset).Find(&result).Error

	return result, err
}

// SaveDomains saves domain records to database. If domain with specific source not presented, creates one.
// If defined combination already in database, updates it and makes it active.
func (r *BlacklistsRepoImpl) SaveDomains(domains []entities.BlacklistedDomain) (int64, error) {
	query := r.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "urn"}, {Name: "source_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"updated_at": time.Now(), "deleted_at": nil}),
	}).Save(&domains)

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
