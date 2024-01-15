package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

// ScanAgent represents remote network scanner agent.
type ScanAgent struct {
	UUID pgtype.UUID `json:"uuid" gorm:"primaryKey"`

	Name        string      `json:"name" gorm:"column:name;size:64;not null"`
	IPAddress   pgtype.Inet `json:"ip_address" gorm:"column:ip_address;type:inet"`
	Host        string      `json:"host" gorm:"column:host;size:128;type:inet"`
	IsActive    bool        `json:"is_active" gorm:"column:is_active;default:true"`
	Description string      `json:"description" gorm:"column:description;size:512;default:No description."`

	// Defines who is the owner of agent.
	Owner     *PlatformUser `json:"owner,omitempty" gorm:"foreignKey:OwnerUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	OwnerUUID pgtype.UUID   `json:"owner_uuid"`

	// Private agents can only be used by their owners.
	IsPrivate bool `json:"is_private" gorm:"column:is_private;default:true"`

	Config datatypes.JSONType[ScanAgentConfiguration] `json:"config"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// ScanAgentConfiguration defines configuration parameters used in agent.
type ScanAgentConfiguration struct {
	HasNMAP bool `json:"has_nmap"`
}
