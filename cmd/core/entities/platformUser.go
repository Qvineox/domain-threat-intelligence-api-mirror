package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

// PlatformUser defines a single system user account.
type PlatformUser struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	FullName     string `json:"FullName" gorm:"column:full_name;size:128;not null"`
	Login        string `json:"Login" gorm:"column:login;size:32;not null;unique"`
	PasswordHash string `json:"-" gorm:"column:password_hash"`
	IsActive     bool   `json:"IsActive" gorm:"column:is_active;default:true"`

	// Defines which roles user has
	Roles []PlatformUserRole `json:"Roles,omitempty" gorm:"many2many:platform_users_roles;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}
