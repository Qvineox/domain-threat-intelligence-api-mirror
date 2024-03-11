package networkEntities

import (
	"gorm.io/gorm"
	"time"
)

// NetworkNodeType is linked to jobEntities.TargetType
type NetworkNodeType struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

var DefaultNetworkNodeTypes = []NetworkNodeType{
	{
		ID:          1,
		Name:        "CIDR/IP",
		Description: "IP address",
	},
	{
		ID:          2,
		Name:        "Domain",
		Description: "Internet Domain",
	},
	{
		ID:          3,
		Name:        "EMail",
		Description: "Email address",
	},
	{
		ID:          4,
		Name:        "URL",
		Description: "URL address",
	},
}
