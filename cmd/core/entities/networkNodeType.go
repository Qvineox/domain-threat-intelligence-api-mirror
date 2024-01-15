package entities

import "gorm.io/gorm"

type NetworkNodeType struct {
	gorm.Model

	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`
}
