package authEntities

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims used to auth user in the system. This struct is usually created by TokenFactory
type AccessTokenClaims struct {
	jwt.RegisteredClaims

	UserID  uint64    `json:"user_id"`
	RoleIDs *[]uint64 `json:"role_ids,omitempty"`
}

func (claims AccessTokenClaims) Sing(method *jwt.SigningMethodHMAC, key []byte) (string, error) {
	token := jwt.NewWithClaims(method, claims)

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return tokenString, err
}

func NewAccessTokenClaimsFromToken(token *jwt.Token) (AccessTokenClaims, error) {
	c, ok := token.Claims.(AccessTokenClaims)
	if !ok {
		return AccessTokenClaims{}, errors.New("token structure invalid")
	}

	if token.Valid {
		return c, nil
	}

	return AccessTokenClaims{}, errors.New("unexpected error")
}
