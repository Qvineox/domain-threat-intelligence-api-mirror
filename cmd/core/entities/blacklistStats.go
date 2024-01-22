package entities

import "time"

type BlacklistedByDate struct {
	Date  time.Time `json:"Date" gorm:"column:date"` // labels
	Count uint64    `json:"Count" gorm:"column:count"`
	Type  string    `json:"Type" gorm:"column:type"`
}
