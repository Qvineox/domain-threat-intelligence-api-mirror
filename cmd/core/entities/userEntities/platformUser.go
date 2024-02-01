package userEntities

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"gorm.io/gorm"
	"time"
)

// PlatformUser defines a single system user account.
type PlatformUser struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	FullName     string `json:"FullName" gorm:"column:full_name;size:128;not null"`
	Login        string `json:"Login" gorm:"column:login;size:32;not null;unique"`
	Email        string `json:"Email" gorm:"column:email;"`
	PasswordHash string `json:"-" gorm:"column:password_hash"`
	IsActive     bool   `json:"IsActive" gorm:"column:is_active;default:true"`

	// Defines which roles user has
	Roles []PlatformUserRole `json:"Roles,omitempty" gorm:"many2many:platform_users_roles;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

func NewPlatformUser(fullName, login, email, saltedPassword string, isActive bool) (*PlatformUser, error) {
	if len(saltedPassword) == 0 || len(login) == 0 {
		return nil, errors.New("saltedPassword or login empty")
	}

	hasher := sha512.New()
	hasher.Write([]byte(saltedPassword))

	hashedPass := hasher.Sum(nil)

	return &PlatformUser{
		FullName:     fullName,
		Login:        login,
		Email:        email,
		PasswordHash: hex.EncodeToString(hashedPass),
		IsActive:     isActive,
	}, nil
}

func (user *PlatformUser) SetRoles(roleIDs []uint64) error {
	var userRoles []PlatformUserRole

	for _, id := range roleIDs {
		for _, defRole := range DefaultUserRoles {
			if id == defRole.ID {
				userRoles = append(userRoles, defRole)
				continue
			}

			return errors.New(fmt.Sprintf("role with id %d not found", id))
		}
	}

	user.Roles = userRoles
	return nil
}
