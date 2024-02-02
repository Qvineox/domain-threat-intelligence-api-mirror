package blacklistEntities

import (
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

type BlacklistImportEvent struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	Summary    datatypes.JSONType[BlacklistImportEventSummary] `json:"Summary" gorm:"column:summary"`
	Type       string                                          `json:"Type" gorm:"column:type"`
	IsComplete bool                                            `json:"IsComplete" gorm:"column:is_complete"`

	// CreatedBy defines import event creator identity
	CreatedBy   *userEntities.PlatformUser `json:"CreatedBy"`
	CreatedByID *uint64                    `json:"CreatedByID" gorm:"column:created_by_id"`

	CreatedAt time.Time      `json:"CreatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

type BlacklistImportEventSummary struct {
	Imported struct {
		Total   int64 `json:"Total"`
		IPs     int64 `json:"IPs"`
		URLs    int64 `json:"URLs"`
		Domains int64 `json:"Domains"`
		Emails  int64 `json:"Emails"`
	} `json:"Imported"`
	New struct {
		Total   int64 `json:"Total"`
		IPs     int64 `json:"IPs"`
		URLs    int64 `json:"URLs"`
		Domains int64 `json:"Domains"`
		Emails  int64 `json:"Emails"`
	} `json:"New"`
	Skipped int64 `json:"Skipped"`
	Errored int   `json:"Errored"`
}
