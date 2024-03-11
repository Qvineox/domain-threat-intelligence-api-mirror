package networkEntities

import "time"

type NetworkNodeSearchFilter struct {
	Offset           int        `json:"Offset" form:"offset"`
	Limit            int        `json:"Limit" form:"limit"`
	TypeIDs          []uint64   `json:"TypeId" form:"type_id[]" binding:"dive"`
	CreatedAfter     *time.Time `json:"CreatedAfter" form:"created_after" time_format:"2006-01-02"`
	CreatedBefore    *time.Time `json:"CreatedBefore" form:"created_before" time_format:"2006-01-02"`
	DiscoveredAfter  *time.Time `json:"DiscoveredAfter" form:"discovered_after" time_format:"2006-01-02"`
	DiscoveredBefore *time.Time `json:"DiscoveredBefore" form:"discovered_before" time_format:"2006-01-02"`
	SearchString     string     `json:"SearchString" form:"search_string"`
}
