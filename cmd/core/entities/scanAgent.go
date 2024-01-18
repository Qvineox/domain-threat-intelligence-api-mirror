package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

// ScanAgent represents remote network scanner agent.
type ScanAgent struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid"`

	Name        string      `json:"Name" gorm:"column:name;size:64;not null"`
	IPAddress   pgtype.Inet `json:"IPAddress" gorm:"column:ip_address;type:inet"`
	Host        string      `json:"Host" gorm:"column:host;size:128;type:inet"`
	IsActive    bool        `json:"IsActive" gorm:"column:is_active;default:true"`
	Description string      `json:"Description" gorm:"column:description;size:512;default:No description."`

	// Defines who is the owner of agent.
	Owner     *PlatformUser `json:"Owner,omitempty" gorm:"foreignKey:OwnerUUID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	OwnerUUID pgtype.UUID   `json:"OwnerUUID"`

	// Private agents can only be used by their owners.
	IsPrivate bool `json:"IsPrivate" gorm:"column:is_private;default:true"`

	Config datatypes.JSONType[ScanAgentConfiguration] `json:"config"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// ScanAgentConfiguration defines configuration parameters used in agent.
type ScanAgentConfiguration struct {
	HasNMAP bool `json:"HasNMAP"`
}
