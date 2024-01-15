package entities

import (
	"gorm.io/gorm"
	"time"
)

type PlatformUserRole struct {
	IsActive bool `json:"IsActive" gorm:"column:is_active;default:true"`

	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`

	gorm.Model
}

const (
	RoleLogin uint = iota + 1
	RoleAdmin
	RoleBlacklistImport
)

var DefaultUserRoles = []PlatformUserRole{
	{
		Name:        "Auth",
		Description: "Определяет может ли пользователи авторизоваться в системе",
		Model: gorm.Model{
			ID:        RoleLogin,
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "Admin",
		Description: "Является ли пользователь администратором",
		Model: gorm.Model{
			ID:        RoleAdmin,
			UpdatedAt: time.Now(),
		},
	},
	{
		Name:        "Can import blacklists",
		Description: "Определяет может ли пользователи импортировать списки блокировок",
		Model: gorm.Model{
			ID:        RoleBlacklistImport,
			UpdatedAt: time.Now(),
		},
	},
}
