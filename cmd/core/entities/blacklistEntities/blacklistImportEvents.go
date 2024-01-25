package blacklistEntities

import (
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

type BlacklistImportEvent struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	Summary datatypes.JSONType[BlacklistImportEventSummary] `json:"Summary" gorm:"column:summary"`
	Type    string                                          `json:"Type" gorm:"column:type"`

	// TODO: add CreatedBy field

	CreatedAt time.Time      `json:"CreatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

type BlacklistImportEventSummary struct {
	TotalHosts uint64 `json:"AddedHosts"`

	AddedURLs    uint64 `json:"AddedURLs"`
	AddedIPs     uint64 `json:"AddedIPs"`
	AddedDomains uint64 `json:"AddedDomains"`
	AddedEmails  uint64 `json:"AddedEmails"`
}
