package blacklistEntities

import "time"

type BlacklistSearchFilter struct {
	Offset           int        `json:"Offset" form:"offset"`
	Limit            int        `json:"Limit" form:"limit" binding:"required"`
	SourceIDs        []uint64   `json:"SourceId" form:"source_id[]" binding:"dive"`
	IsActive         *bool      `json:"IsActive" form:"is_active"`
	CreatedAfter     *time.Time `json:"CreatedAfter" form:"created_after" time_format:"2006-01-02"`
	CreatedBefore    *time.Time `json:"CreatedBefore" form:"created_before" time_format:"2006-01-02"`
	DiscoveredAfter  *time.Time `json:"DiscoveredAfter" form:"discovered_after" time_format:"2006-01-02"`
	DiscoveredBefore *time.Time `json:"DiscoveredBefore" form:"discovered_before" time_format:"2006-01-02"`
	SearchString     string     `json:"SearchString" form:"search_string"`
}

type BlacklistExportFilter struct {
	SourceIDs        []uint64   `json:"SourceId" form:"source_id[]" binding:"dive"`
	IsActive         *bool      `json:"IsActive" form:"is_active"`
	OnlyNew          *bool      `json:"OnlyNew" form:"only_new"`
	CreatedAfter     *time.Time `json:"CreatedAfter" form:"created_after" time_format:"2006-01-02" binding:"required"`
	CreatedBefore    *time.Time `json:"CreatedBefore" form:"created_before" time_format:"2006-01-02" binding:"required"`
	DiscoveredAfter  *time.Time `json:"DiscoveredAfter" form:"discovered_after" time_format:"2006-01-02"`
	DiscoveredBefore *time.Time `json:"DiscoveredBefore" form:"discovered_before" time_format:"2006-01-02"`
}

type BlacklistImportEventFilter struct {
	Offset        int        `json:"Offset" form:"offset"`
	Limit         int        `json:"Limit" form:"limit" binding:"required"`
	Type          string     `json:"Type" form:"type"`
	CreatedAfter  *time.Time `json:"CreatedAfter" form:"created_after" time_format:"2006-01-02"`
	CreatedBefore *time.Time `json:"CreatedBefore" form:"created_before" time_format:"2006-01-02"`
}
