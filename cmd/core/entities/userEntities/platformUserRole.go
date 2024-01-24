package userEntities

import (
	"gorm.io/gorm"
	"time"
)

type PlatformUserRole struct {
	ID uint64 `json:"UUID" gorm:"primaryKey"`

	IsActive    bool   `json:"IsActive" gorm:"column:is_active;default:true"`
	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

const (
	RoleLogin uint64 = iota + 1
	RoleAdmin
	RoleBlacklistImport
)

var DefaultUserRoles = []PlatformUserRole{
	{
		ID:          RoleLogin,
		UpdatedAt:   time.Now(),
		Name:        "Auth",
		Description: "Определяет может ли пользователи авторизоваться в системе",
	},
	{
		ID:          RoleAdmin,
		UpdatedAt:   time.Now(),
		Name:        "Admin",
		Description: "Является ли пользователь администратором",
	},
	{
		ID:          RoleBlacklistImport,
		UpdatedAt:   time.Now(),
		Name:        "Can import blacklists",
		Description: "Определяет может ли пользователи импортировать списки блокировок",
	},
}
