package entities

import "github.com/jackc/pgtype"

// NetworkNodeLink is used to represent a distributed network of interconnections between network nodes.
type NetworkNodeLink struct {
	UUID pgtype.UUID `json:"uuid" gorm:"primaryKey"`

	SourceNode     NetworkNode `json:"source_node" gorm:"foreignKey:SourceNodeUUID;constraint:OnUpdate:CASCADE,OnDelete:DELETE;"`
	SourceNodeUUID pgtype.UUID `json:"source_node_uuid"`

	DestinationNode     NetworkNode `json:"destination_node" gorm:"foreignKey:DestinationNodeUUID;constraint:OnUpdate:CASCADE,OnDelete:DELETE;"`
	DestinationNodeUUID pgtype.UUID `json:"destination_node_uuid"`

	// LinkType determines the nature of the link between two nodes.
	LinkType string `json:"link_type"`
}
