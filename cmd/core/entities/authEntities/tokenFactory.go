package authEntities

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type TokenFactory struct {
	issuer         string
	subject        string
	audience       []string
	expireDuration time.Duration
}

func NewTokenFactory(issuer, subject string, audience []string, expiresInMinutes time.Duration) *TokenFactory {
	return &TokenFactory{issuer: issuer, subject: subject, audience: audience, expireDuration: expiresInMinutes}
}

func (f *TokenFactory) ProduceAccessToken(roleIDs []uint64) AccessTokenClaims {
	now := time.Now()

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   f.subject,
			Audience:  f.audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(f.expireDuration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		RoleIDs: roleIDs,
	}

	return claims
}

func (f *TokenFactory) ProduceRefreshToken() RefreshTokenClaims {
	now := time.Now()

	claims := RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    f.issuer,
			Subject:   f.subject,
			Audience:  f.audience,
			ExpiresAt: jwt.NewNumericDate(now.Add(f.expireDuration)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	return claims
}
