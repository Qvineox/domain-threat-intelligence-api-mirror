package blacklistEntities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type BlacklistedHost struct {
	UUID pgtype.UUID `json:"UUID" gorm:"primaryKey"`

	Type        string     `json:"Type" gorm:"column:type"` // domain, url or IP
	Host        string     `json:"Host" gorm:"column:host"`
	Description string     `json:"Description" gorm:"column:description"`
	Status      HostStatus `json:"Status" gorm:"-"`

	// Source defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty"`
	SourceID uint64           `json:"SourceID" gorm:"column:source_id"`

	// ImportEvent describes import session from where blacklisted host was added
	ImportEvent   *BlacklistImportEvent `json:"ImportEvent,omitempty"`
	ImportEventID *uint64               `json:"ImportEventID" gorm:"column:import_event_id"`

	// DiscoveredAt sets date of discovery, provided by source or inserted automatically on create
	DiscoveredAt time.Time `json:"DiscoveredAt" gorm:"autoCreateTime"`

	CreatedAt time.Time      `json:"CreatedAt" gorm:"column:created_at"`
	UpdatedAt time.Time      `json:"UpdatedAt" gorm:"column:updated_at"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"column:deleted_at"`
}

type HostStatus string

const (
	HostStatusNew     HostStatus = "new"
	HostStatusUpdated            = "updated"
	HostStatusDefault            = "default"
	HostStatusDeleted            = "deleted"
)

func (h *BlacklistedHost) FromIP(ip BlacklistedIP) {
	h.Host = ip.IPAddress.IPNet.String()

	h.UUID = ip.UUID
	h.Type = "ip"

	h.Source = ip.Source
	h.SourceID = ip.SourceID

	h.Description = ip.Description
	h.CreatedAt = ip.CreatedAt
	h.UpdatedAt = ip.UpdatedAt
	h.DeletedAt = ip.DeletedAt

	h.Status = HostStatusDefault
}

func (h *BlacklistedHost) FromDomain(ip BlacklistedDomain) {
	h.Host = ip.URN
	h.UUID = ip.UUID
	h.Type = "domain"

	h.Source = ip.Source
	h.SourceID = ip.SourceID

	h.Description = ip.Description
	h.CreatedAt = ip.CreatedAt
	h.UpdatedAt = ip.UpdatedAt
	h.DeletedAt = ip.DeletedAt

	h.Status = HostStatusDefault
}

func (h *BlacklistedHost) FromURL(ip BlacklistedURL) {
	h.Host = ip.URL
	h.UUID = ip.UUID
	h.Type = "url"

	h.Source = ip.Source
	h.SourceID = ip.SourceID

	h.Description = ip.Description
	h.CreatedAt = ip.CreatedAt
	h.UpdatedAt = ip.UpdatedAt
	h.DeletedAt = ip.DeletedAt

	h.Status = HostStatusDefault
}
