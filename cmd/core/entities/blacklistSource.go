package entities

import (
	"gorm.io/gorm"
	"time"
)

// BlacklistSource defined original sources of indicators
type BlacklistSource struct {
	Name        string `json:"Name" gorm:"column:name;not_null;unique"`
	Description string `json:"Description" gorm:"column:description;size:512;default:No description."`

	gorm.Model
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
		Name:        "Manual",
		Description: "Ручной ввод пользователями системы",
		Model: gorm.Model{
			ID:        uint(SourceManual),
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "FinCERT",
		Description: "Центр взаимодействия и реагирования Департамента информационной безопасности, специальное структурное подразделение Банка России.",
		Model: gorm.Model{
			ID:        uint(SourceFinCERT),
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "Kaspersky",
		Description: "Автоматический импорт индикаторов от Kaspersky.",
		Model: gorm.Model{
			ID:        uint(SourceKaspersky),
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "DrWEB",
		Description: "Автоматический импорт индикаторов от DrWeb.",
		Model: gorm.Model{
			ID:        uint(SourceDrWeb),
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "Unknown",
		Description: "Автоматический импорт индикаторов из неопределенного источника.",
		Model: gorm.Model{
			ID:        uint(SourceUnknown),
			UpdatedAt: time.Now(),
		},
	},
}
