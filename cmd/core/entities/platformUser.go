package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

// PlatformUser defines a single system user account.
type PlatformUser struct {
	UUID pgtype.UUID `json:"uuid" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	FullName     string `json:"full_name" gorm:"column:full_name;size:128;not null"`
	Login        string `json:"login" gorm:"column:login;size:32;not null;unique"`
	PasswordHash string `json:"password_hash" gorm:"column:password_hash"`
	IsActive     bool   `json:"is_active" gorm:"column:is_active;default:true"`

	// Defines which roles user has
	Roles []PlatformUserRole `json:"roles" gorm:"many2many:platform_users_roles;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}
