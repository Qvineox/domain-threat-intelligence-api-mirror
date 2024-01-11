package entities

import "gorm.io/gorm"

type PlatformUserRole struct {
	gorm.Model

	IsActive bool `json:"is_active" gorm:"column:is_active;default:true"`

	Name        string `json:"name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"description" gorm:"column:description;size:128;default:No description."`
}
