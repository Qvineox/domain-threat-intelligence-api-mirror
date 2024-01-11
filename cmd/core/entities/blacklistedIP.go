package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
)

type BlacklistedIP struct {
	gorm.Model

	IPAddress pgtype.Inet `json:"ip_address" gorm:"column:ip_address;type:inet;not_null"`
	Source    string      `json:"source" gorm:"column:source;size:128;default:manual input"`
}
