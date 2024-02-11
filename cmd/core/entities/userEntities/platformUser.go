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
	Permissions []PlatformUserPermission `json:"Permissions,omitempty" gorm:"many2many:platform_users_permissions;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

func NewPlatformUser(fullName, login, email, saltedPassword string, isActive bool) (*PlatformUser, error) {
	if len(saltedPassword) == 0 || len(login) == 0 {
		return nil, errors.New("salted password or login empty")
	}

	h := sha512.New()
	h.Write([]byte(saltedPassword))

	hashedPass := h.Sum(nil)

	return &PlatformUser{
		FullName:     fullName,
		Login:        login,
		Email:        email,
		PasswordHash: hex.EncodeToString(hashedPass),
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     isActive,
	}, nil
}

func (user *PlatformUser) SetPasswordHash(saltedPassword string) error {
	if len(saltedPassword) == 0 {
		return errors.New("salted password empty")
	}

	h := sha512.New()
	h.Write([]byte(saltedPassword))

	hashedPass := h.Sum(nil)

	user.PasswordHash = hex.EncodeToString(hashedPass)

	return nil
}

func (user *PlatformUser) ComparePassword(saltedPassword string) (bool, error) {
	if len(saltedPassword) == 0 {
		return false, errors.New("salted password empty")
	}

	h := sha512.New()
	h.Write([]byte(saltedPassword))
	hashedPass := h.Sum(nil)

	return user.PasswordHash == hex.EncodeToString(hashedPass), nil
}

func (user *PlatformUser) SetPermissions(roleIDs []uint64) error {
	var userRoles []PlatformUserPermission

	for _, id := range roleIDs {
		var found = false

		for _, defRole := range DefaultUserPermissions {
			if id == defRole.ID {
				userRoles = append(userRoles, defRole)
				found = true
				break
			}
		}

		if !found {
			return errors.New(fmt.Sprintf("role with id %d not found", id))
		}
	}

	user.Permissions = userRoles
	return nil
}

func (user *PlatformUser) GetRoleIDs() []uint64 {
	var ids []uint64

	for _, r := range user.Permissions {
		ids = append(ids, r.ID)
	}

	return ids
}
