package entities

import "gorm.io/gorm"

type NetworkNodeType struct {
	gorm.Model

	Name        string `json:"name" gorm:"column:name;not null;unique"`
	Description string `json:"description" gorm:"column:description;default:No description."`
}
