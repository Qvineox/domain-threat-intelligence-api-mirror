package entities

import (
	"github.com/jackc/pgtype"
	"gorm.io/gorm"
	"time"
)

type BlacklistedHost struct {
	UUID pgtype.UUID `json:"UUID"`

	Type        string `json:"Type"` // domain, url or IP
	Host        string `json:"Host"`
	Description string `json:"Description"`

	// Defines source from where blacklisted host was added
	Source   *BlacklistSource `json:"Source,omitempty"`
	SourceID uint64           `json:"SourceID"`

	CreatedAt time.Time      `json:"CreatedAt"`
	UpdatedAt time.Time      `json:"UpdatedAt"`
	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty"`
}

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
}
