package entities

import (
	"gorm.io/gorm"
	"time"
)

type BlacklistSource struct {
	Name        string `json:"Name" gorm:"column:name;not_null;unique"`
	Description string `json:"Description" gorm:"column:description;size:512;default:No description."`

	gorm.Model
}

const (
	SourceManual uint = iota + 1
	SourceFinCERTManual
	SourceFinCERTAuto
)

// DefaultSources describes predefined sources of blacklists and IoCs. Always updates on migration.
var DefaultSources = [3]BlacklistSource{
	{
		Name:        "Manual",
		Description: "Ручной ввод пользователями системы",
		Model: gorm.Model{
			ID:        SourceManual,
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "FinCERT_Manual",
		Description: "Ручной импорт. Центр взаимодействия и реагирования Департамента информационной безопасности, специальное структурное подразделение Банка России.",
		Model: gorm.Model{
			ID:        SourceFinCERTManual,
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "FinCERT_Auto",
		Description: "Автоматический импорт. Центр взаимодействия и реагирования Департамента информационной безопасности, специальное структурное подразделение Банка России.",
		Model: gorm.Model{
			ID:        SourceFinCERTAuto,
			UpdatedAt: time.Now(),
		},
	},
}
