package userEntities

import (
	"gorm.io/gorm"
	"time"
)

type PlatformUserPermission struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	IsActive    bool   `json:"IsActive" gorm:"column:is_active;default:true"`
	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

type PlatformUserRolesPreset struct {
	Name        string   `json:"Name"`
	Description string   `json:"Description"`
	RoleIDs     []uint64 `json:"PermissionIDs"`
}

var DefaultUserPermissionPresets = []PlatformUserRolesPreset{
	{
		Name:        "Default User",
		Description: "Базовый функционал для входа.",
		RoleIDs:     []uint64{1001, 4001},
	},
	{
		Name:        "Operator",
		Description: "Необходимый функционал для работы с платформой.",
		RoleIDs:     []uint64{1001, 4001, 4002, 4003, 4004},
	},
	{
		Name:        "Moderator",
		Description: "Функционал для управления платформой.",
		RoleIDs:     []uint64{1001, 2001, 2002, 2003, 4001, 4002, 4003, 4004},
	},
	{
		Name:        "Hyper Admin",
		Description: "Полный доступ.",
		RoleIDs:     []uint64{1001, 1002, 2001, 2002, 2003, 4001, 4002, 4003, 4004, 6001, 6002},
	},
}

// DefaultUserPermissions describes all user roles in the system.
// Naming convention -> module/service :: permission
var DefaultUserPermissions = []PlatformUserPermission{
	{
		ID:          1001,
		IsActive:    false,
		Name:        "auth::login",
		Description: "Возможность входа в систему",
	},
	{
		ID:          1002,
		IsActive:    true,
		Name:        "auth::admin",
		Description: "Администратор",
	},
	{
		ID:          2001,
		IsActive:    true,
		Name:        "users::view",
		Description: "Просмотр списка пользователей",
	},
	{
		ID:          2002,
		IsActive:    true,
		Name:        "users::register",
		Description: "Регистрация новых пользователей",
	},
	{
		ID:          2003,
		IsActive:    true,
		Name:        "users::modify",
		Description: "Изменение списка пользователей",
	},
	{
		ID:          4001,
		IsActive:    true,
		Name:        "blacklists::view",
		Description: "Просмотр списка блокировок",
	},
	{
		ID:          4002,
		IsActive:    true,
		Name:        "blacklists::modify",
		Description: "Изменение списка блокировок",
	},
	{
		ID:          4003,
		IsActive:    true,
		Name:        "blacklists::import",
		Description: "Импорт блокировок",
	},
	{
		ID:          4004,
		IsActive:    true,
		Name:        "blacklists::export",
		Description: "Экспорт блокировок",
	},
	{
		ID:          6001,
		IsActive:    true,
		Name:        "config::view",
		Description: "Просмотр конфигурации платформы",
	},
	{
		ID:          6002,
		IsActive:    true,
		Name:        "config::modify",
		Description: "Изменение конфигурации платформы",
	},
	{
		ID:          6003,
		IsActive:    true,
		Name:        "config::reset",
		Description: "Сброс конфигурации платформы",
	},
}
