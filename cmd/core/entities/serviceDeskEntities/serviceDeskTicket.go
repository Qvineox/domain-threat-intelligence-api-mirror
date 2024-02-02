package serviceDeskEntities

import (
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

type ServiceDeskTicket struct {
	ID     uint64 `json:"ID" gorm:"primaryKey"`
	System string `json:"System" gorm:"column:system;not null"`

	// TicketID is issued by service desk
	TicketID string `json:"TicketID" gorm:"column:ticket_id"`

	Data datatypes.JSON `json:"Data"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}
