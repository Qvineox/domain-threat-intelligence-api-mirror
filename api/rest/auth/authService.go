package auth

import (
	apiErrors "domain_threat_intelligence_api/api/rest/error"
	"domain_threat_intelligence_api/cmd/core"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type MiddlewareService struct {
	service core.IAuthService

	cached cachedTokens
}

type cachedTokens struct {
	// accessTokens contains access tokens with expiration time
	accessTokens map[string]time.Time
}

func NewMiddlewareService(service core.IAuthService) *MiddlewareService {
	return &MiddlewareService{service: service, cached: cachedTokens{make(map[string]time.Time)}}
}

func (s *MiddlewareService) ValidateAccessToken(accessToken string) bool {
	validUntil, ok := s.cached.accessTokens[accessToken]

	return ok && validUntil.After(time.Now())
}

func (s *MiddlewareService) RefreshAccessToken(refreshToken string) (accessToken, newRefreshToken string, err error) {
	return s.service.Refresh(refreshToken)
}

func (s *MiddlewareService) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("x-api-key")

		if len(token) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, apiErrors.APIError{
				StatusCode:   http.StatusUnauthorized,
				ErrorCode:    apiErrors.AuthFailedErrorCode,
				ErrorMessage: "missing access token",
				ErrorModule:  "auth",
			})
			return
		}

		claims, err := s.service.Validate(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, apiErrors.APIError{
				StatusCode:   http.StatusUnauthorized,
				ErrorCode:    apiErrors.AuthFailedErrorCode,
				ErrorMessage: err.Error(),
				ErrorModule:  "auth",
			})
			return
		}

		c.Set("user_roles", claims.RoleIDs)
		c.Set("user_id", claims.UserID)

		c.Next()
		return
	}
}
