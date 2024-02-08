package authEntities

import (
	"github.com/golang-jwt/jwt/v5"
)

// RefreshTokenClaims used to re-login user automatically and protect from stolen auth data. This struct is usually created by TokenFactory
type RefreshTokenClaims struct {
	jwt.RegisteredClaims
}

func (claims RefreshTokenClaims) Sing(method *jwt.SigningMethodHMAC, key []byte) (string, error) {
	token := jwt.NewWithClaims(method, claims)

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, err
}

func NewRefreshTokenClaims(token *jwt.Token) (RefreshTokenClaims, error) {
	c, ok := token.Claims.(RefreshTokenClaims)
	if ok && token.Valid {
		return c, nil
	}

	return RefreshTokenClaims{}, nil
}
