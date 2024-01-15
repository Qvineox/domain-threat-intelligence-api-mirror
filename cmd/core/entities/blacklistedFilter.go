package entities

import "time"

type BlacklistFilter struct {
	Offset        int        `json:"offset" form:"offset"`
	Limit         int        `json:"limit" form:"limit" binding:"required"`
	SourceIDs     []uint64   `json:"source_id" form:"source_id" binding:"dive"`
	IsActive      *bool      `json:"is_active" form:"is_active"`
	CreatedAfter  *time.Time `json:"created_after" form:"created_after" time_format:"2006-01-02"`
	CreatedBefore *time.Time `json:"created_before" form:"created_before" time_format:"2006-01-02"`
	SearchString  string     `json:"search_string" form:"search_string"`
}
