package entities

import (
	"gorm.io/gorm"
)

type BlacklistedDomain struct {
	gorm.Model

	URN    string `json:"URN" gorm:"column:URN;not_null"`
	Source string `json:"source" gorm:"column:source;default:manual input"`
}
