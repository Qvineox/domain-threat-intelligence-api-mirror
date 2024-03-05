package agentEntities

import (
	"domain_threat_intelligence_api/api/grpc/protoServices"
	"domain_threat_intelligence_api/cmd/core/entities/jobEntities"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"fmt"
	"github.com/jackc/pgtype"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

// ScanAgent represents remote network scanner Agent.
type ScanAgent struct {
	UUID *pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`

	Name        string      `json:"Name" gorm:"column:name;size:64;not null"`
	IPAddress   pgtype.Inet `json:"IPAddress" gorm:"column:ip_address;type:inet"`
	Host        string      `json:"Host" gorm:"column:host;size:128"`
	IsActive    bool        `json:"IsActive" gorm:"column:is_active;default:true"`
	IsHomeBound bool        `json:"IsHomeBound" gorm:"column:is_home_bound;default:true"`
	Description string      `json:"Description" gorm:"column:description;size:512;default:No description."`

	// IsConnected is used to monitor dialer connection
	IsConnected bool `json:"IsConnected" gorm:"-"`

	// MinPriority is minimal job priority that Agent can accept
	MinPriority jobEntities.JobPriority `json:"MinPriority" gorm:"column:min_priority;default:3"`

	// Defines who is the owner of Agent.
	Owner   *userEntities.PlatformUser `json:"Owner,omitempty" gorm:"foreignKey:OwnerID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	OwnerID *uint64                    `json:"OwnerID"`

	// Private agents can only be used by their owners.
	IsPrivate bool `json:"IsPrivate" gorm:"column:is_private;default:true"`

	Config datatypes.JSONType[ScanAgentConfig] `json:"config"`

	// SecurityToken used to validate agents and secure sessions
	SecurityToken string `json:"-" gorm:"column:security_key;size:512;default:Security validation token."`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

func (c *ScanAgent) ToProto() protoServices.AgentConfig {
	apiKeys := c.Config.Data()

	return protoServices.AgentConfig{
		Uuid:        fmt.Sprintf("%x", c.UUID.Bytes),
		Name:        c.Name,
		Address:     c.IPAddress.IPNet.String(),
		IsHomeBound: c.IsHomeBound,
		CreatedAt:   timestamppb.New(c.CreatedAt),
		UpdatedAt:   timestamppb.New(c.UpdatedAt),
		Keys:        apiKeys.GetProtoAPIKeys(),
		MinPriority: protoServices.JobPriority(c.MinPriority),
	}
}
