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

var DefaultUserRoles = []PlatformUserRole{
	{
		ID:          1,
		IsActive:    true,
		Name:        "Auth",
		Description: "Определяет может ли пользователь авторизоваться в системе",
	},
	{
		ID:          2,
		IsActive:    true,
		Name:        "Admin",
		Description: "Является ли пользователь администратором",
	},
	{
		ID:          3,
		IsActive:    true,
		Name:        "Can import blacklists",
		Description: "Определяет может ли пользователи импортировать списки блокировок",
	},
}
