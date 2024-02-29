package networkEntities

import (
	"gorm.io/gorm"
)

type NetworkNodeScanType struct {
	ID uint64 `json:"ID" gorm:"primaryKey"`

	Name        string `json:"Name" gorm:"column:name;size:64;not null;unique"`
	Description string `json:"Description" gorm:"column:description;size:128;default:No description."`

	DeletedAt gorm.DeletedAt `json:"DeletedAt,omitempty" gorm:"index"`
}

type ScanType uint64

// TODO: change provider IDs in proto files (do +1)

const (
	SCAN_TYPE_OSS_VT ScanType = iota + 1
	SCAN_TYPE_OSS_IPQS
	SCAN_TYPE_OSS_SHD
	SCAN_TYPE_OSS_CS
	SCAN_TYPE_OSS_IPWH
)

var DefaultNetworkNodeScanTypes = []NetworkNodeScanType{
	{
		ID:          uint64(SCAN_TYPE_OSS_VT),
		Name:        "Provider VirusTotal",
		Description: "Данные получены из запроса к API VirusTotal",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IPQS),
		Name:        "Provider IPQualityScore",
		Description: "Данные получены из запроса к API IPQualityScore",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_SHD),
		Name:        "Provider Shodan",
		Description: "Данные получены из запроса к API Shodan",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_CS),
		Name:        "Provider CrowdSec",
		Description: "Данные получены из запроса к API CrowdSec",
	},
	{
		ID:          uint64(SCAN_TYPE_OSS_IPWH),
		Name:        "Provider IPWhoIs",
		Description: "Данные получены из запроса к API IPWhoIS",
	},
}
