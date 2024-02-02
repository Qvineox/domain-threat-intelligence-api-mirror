package serviceDeskEntities

import "time"

type ServiceDeskSearchFilter struct {
	Offset        int        `json:"Offset" form:"offset"`
	Limit         int        `json:"Limit" form:"limit" binding:"required"`
	System        string     `json:"System" form:"system"`
	TicketID      string     `json:"TicketID" form:"ticket_id"`
	CreatedAfter  *time.Time `json:"CreatedAfter" form:"created_after" time_format:"2006-01-02"`
	CreatedBefore *time.Time `json:"CreatedBefore" form:"created_before" time_format:"2006-01-02"`
}
