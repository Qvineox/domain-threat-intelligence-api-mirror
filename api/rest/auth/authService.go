package auth

import (
	"domain_threat_intelligence_api/cmd/core"
	"time"
)

type TokenMiddlewareService struct {
	service core.IAuthService

	cachedValues struct {
		// accessTokens contains access tokens with expiration time
		accessTokens map[string]time.Time
	}
}

func (s *TokenMiddlewareService) ValidateAccessToken(accessToken string) bool {
	validUntil, ok := s.cachedValues.accessTokens[accessToken]

	return ok && validUntil.After(time.Now())
}

func (s *TokenMiddlewareService) RefreshAccessToken(refreshToken string) (accessToken, newRefreshToken string, err error) {
	return s.service.Refresh(refreshToken)
}
