package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities/serviceDeskEntities"
	"gorm.io/gorm"
)

type ServiceDeskRepoImpl struct {
	*gorm.DB
}

func NewServiceDeskRepoImpl(DB *gorm.DB) *ServiceDeskRepoImpl {
	return &ServiceDeskRepoImpl{DB: DB}
}

func (r *ServiceDeskRepoImpl) SaveTicket(ticket serviceDeskEntities.ServiceDeskTicket) (serviceDeskEntities.ServiceDeskTicket, error) {
	err := r.Save(&ticket).Error
	if err != nil {
		return serviceDeskEntities.ServiceDeskTicket{}, err
	}

	return ticket, nil
}

func (r *ServiceDeskRepoImpl) SelectTicketsByFilter(filter serviceDeskEntities.ServiceDeskSearchFilter) ([]serviceDeskEntities.ServiceDeskTicket, error) {
	query := r.Model(&serviceDeskEntities.ServiceDeskTicket{})

	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", filter.CreatedAfter)
	}

	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", filter.CreatedBefore)
	}

	if len(filter.TicketID) > 0 {
		query = query.Where("ticket_id LIKE ?", "%"+filter.TicketID+"%")
	}

	if len(filter.System) > 0 {
		query = query.Where("system = ?", filter.System)
	}

	if filter.Limit != 0 {
		query = query.Limit(filter.Limit)
	}

	var result []serviceDeskEntities.ServiceDeskTicket
	err := query.Offset(filter.Offset).Order("created_at DESC, updated_at DESC, ID DESC").Find(&result).Error

	return result, err
}

func (r *ServiceDeskRepoImpl) DeleteTicket(id uint64) error {
	query := r.Delete(&serviceDeskEntities.ServiceDeskTicket{
		ID: id,
	})

	return query.Error
}
