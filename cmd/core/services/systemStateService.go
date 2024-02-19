package services

import (
	"domain_threat_intelligence_api/cmd/integrations/naumen"
	"domain_threat_intelligence_api/cmd/mail"
)

type SystemStateServiceImpl struct {
	dynamicConfig ISystemDynamicConfig
}

type ISystemDynamicConfig interface {
	naumen.INaumenDynamicConfig
	mail.ISMTPDynamicConfig

	GetCurrentState() ([]byte, error)
	SetDefaultValues() error
}

func NewSystemStateServiceImpl(dynamicConfig ISystemDynamicConfig) *SystemStateServiceImpl {
	return &SystemStateServiceImpl{dynamicConfig: dynamicConfig}
}

func (s *SystemStateServiceImpl) RetrieveDynamicConfig() ([]byte, error) {
	return s.dynamicConfig.GetCurrentState()
}

func (s *SystemStateServiceImpl) ReturnToDefault() error {
	return s.dynamicConfig.SetDefaultValues()
}

func (s *SystemStateServiceImpl) UpdateSMTPConfig(enabled, SSL, UseAuth bool, host, user, from, password string, port int) error {
	return s.dynamicConfig.SetSMTPConfig(enabled, SSL, UseAuth, host, user, from, password, port)
}

func (s *SystemStateServiceImpl) UpdateNSDCredentials(enabled bool, host, clientKey string, clientID, clientGroupID uint64) error {
	return s.dynamicConfig.SetNaumenConfig(enabled, host, clientKey, clientID, clientGroupID)
}

func (s *SystemStateServiceImpl) UpdateNSDBlacklistServiceConfig(agreementID, slm uint64, callType string, types []string) error {
	return s.dynamicConfig.SetNaumenBlacklistServiceConfig(agreementID, slm, callType, types)
}
