package networkEntities

import (
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
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
		ID:          uint64(jobEntities.HOST_TYPE_CIDR) + 1,
		Name:        "CIDR/IP",
		Description: "IP address",
	},
	{
		ID:          uint64(jobEntities.HOST_TYPE_DOMAIN) + 1,
		Name:        "Domain",
		Description: "Internet Domain",
	},
	{
		ID:          uint64(jobEntities.HOST_TYPE_EMAIL) + 1,
		Name:        "EMail",
		Description: "Email address",
	},
	{
		ID:          uint64(jobEntities.HOST_TYPE_URL) + 1,
		Name:        "URL",
		Description: "URL address",
	},
}
