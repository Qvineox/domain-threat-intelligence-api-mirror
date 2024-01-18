package entities

import "github.com/jackc/pgtype"

// NetworkNodeLink is used to represent a distributed network of interconnections between network nodes.
type NetworkNodeLink struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey;type:uuid"`

	SourceNode     *NetworkNode `json:"SourceNode,omitempty" gorm:"foreignKey:SourceNodeUUID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	SourceNodeUUID pgtype.UUID  `json:"SourceNodeUuid"`

	DestinationNode     *NetworkNode `json:"DestinationNode,omitempty" gorm:"foreignKey:DestinationNodeUUID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	DestinationNodeUUID pgtype.UUID  `json:"DestinationNodeUuid"`

	// LinkType determines the nature of the link between two nodes.
	LinkType string `json:"LinkType" gorm:"size:128"`
}
