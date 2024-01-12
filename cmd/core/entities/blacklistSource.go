package entities

import (
	"gorm.io/gorm"
)

type BlacklistSource struct {
	Name        string `json:"name" gorm:"column:name;not_null;unique"`
	Description string `json:"description" gorm:"column:description;size:512;default:No description."`

	gorm.Model
}
