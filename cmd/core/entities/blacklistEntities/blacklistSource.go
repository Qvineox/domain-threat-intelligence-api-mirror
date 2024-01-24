package blacklistEntities

import (
	"gorm.io/gorm"
	"time"
)

// BlacklistSource defined original sources of indicators
type BlacklistSource struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	Name        string `json:"Name" gorm:"column:name;not_null;unique"`
	Description string `json:"Description" gorm:"column:description;size:512;default:No description."`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

const (
	SourceManual uint64 = iota + 1
	SourceFinCERT
	SourceKaspersky
	SourceDrWeb
	SourceUnknown
)

// DefaultSources describes predefined sources of blacklists and IoCs. Always updates on migration.
var DefaultSources = [5]BlacklistSource{
	{
		ID:          SourceManual,
		UpdatedAt:   time.Now(),
		Name:        "Manual",
		Description: "Ручной ввод пользователями системы",
	},
	{
		ID:          SourceFinCERT,
		UpdatedAt:   time.Now(),
		Name:        "FinCERT",
		Description: "Центр взаимодействия и реагирования Департамента информационной безопасности, специальное структурное подразделение Банка России.",
	},
	{
		ID:          SourceKaspersky,
		UpdatedAt:   time.Now(),
		Name:        "Kaspersky",
		Description: "Автоматический импорт индикаторов от Kaspersky.",
	},
	{
		ID:          SourceDrWeb,
		UpdatedAt:   time.Now(),
		Name:        "DrWEB",
		Description: "Автоматический импорт индикаторов от DrWeb.",
	},
	{
		ID:          SourceUnknown,
		UpdatedAt:   time.Now(),
		Name:        "Unknown",
		Description: "Автоматический импорт индикаторов из неопределенного источника.",
	},
}
