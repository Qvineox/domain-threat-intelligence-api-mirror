package authEntities

import (
	"github.com/golang-jwt/jwt/v5"
)

// AccessTokenClaims used to auth user in the system. This struct is usually created by TokenFactory
type AccessTokenClaims struct {
	jwt.RegisteredClaims

	RoleIDs []uint64 `json:"role_ids"`
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
	if ok && token.Valid {
		return c, nil
	}

	return AccessTokenClaims{}, nil
}
