package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/authEntities"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgtype"
	"github.com/nbutton23/zxcvbn-go"
	"strings"
	"time"
)

type AuthServiceImpl struct {
	repo core.IUsersRepo

	domain string

	salt            string
	accessTokenKey  []byte
	refreshTokenKey []byte

	signingMethod *jwt.SigningMethodHMAC

	accessTokenFactory, refreshTokenFactory *authEntities.TokenFactory
}

func NewAuthServiceImpl(repo core.IUsersRepo, salt, domain string) *AuthServiceImpl {
	s := AuthServiceImpl{repo: repo, salt: salt, domain: domain, signingMethod: jwt.SigningMethodHS512}
	s.accessTokenKey = []byte("5xLJT9hThRym6u")
	s.accessTokenFactory = authEntities.NewTokenFactory(domain, "access_token", []string{"users"}, 20*time.Minute)

	s.refreshTokenKey = []byte("9WJrdq7imvMgmf")
	s.refreshTokenFactory = authEntities.NewTokenFactory(domain, "refresh_token", []string{"users"}, 48*60*time.Minute)

	return &s
}

func (s *AuthServiceImpl) GetDomain() string {
	return s.domain
}

func (s *AuthServiceImpl) ConfirmEmail(confirmationUUID pgtype.UUID) error {
	//TODO implement me
	panic("implement me")
}

func (s *AuthServiceImpl) Register(login, password, fullName, email string, roleIDs []uint64) (uint64, error) {
	if len(password) == 0 || len(login) == 0 {
		return 0, errors.New("password or login empty")
	}

	if !s.isValidByPasswordPolicy(password) {
		return 0, errors.New("password not valid by policy")
	}

	newUser, err := userEntities.NewPlatformUser(fullName, login, email, s.withSalt(password), true)
	if err != nil {
		return 0, err
	}

	err = newUser.SetPermissions(roleIDs)
	if err != nil {
		return 0, err
	}

	return s.repo.InsertUser(*newUser)
}

func (s *AuthServiceImpl) Login(login, password string) (accessToken, refreshToken string, err error) {
	user, err := s.repo.SelectUserByLogin(login)
	if err != nil {
		return "", "", err
	}

	if user.ID == 0 {
		return "", "", errors.New("user not found")
	}

	isValid, err := user.ComparePassword(s.withSalt(password))
	if err != nil {
		return "", "", err
	}

	if !isValid {
		return "", "", errors.New("password invalid")
	}

	accessToken, err = s.accessTokenFactory.ProduceAccessToken(user.GetRoleIDs(), user.ID).Sing(s.signingMethod, s.accessTokenKey)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.accessTokenFactory.ProduceRefreshToken(user.ID).Sing(s.signingMethod, s.refreshTokenKey)
	if err != nil {
		return "", "", err
	}

	user.RefreshToken = refreshToken
	err = s.repo.UpdateUserWithRefreshToken(user)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthServiceImpl) ChangePassword(user userEntities.PlatformUser, oldPassword, newPassword string) (userEntities.PlatformUser, error) {
	ok, err := user.ComparePassword(s.withSalt(oldPassword))
	if err != nil {
		return userEntities.PlatformUser{}, err
	} else if !ok {
		return user, errors.New("password invalid")
	}

	if !s.isValidByPasswordPolicy(newPassword) {
		return user, errors.New("password not valid by policy")
	}

	err = user.SetPasswordHash(s.withSalt(newPassword))
	if err != nil {
		return user, err
	}

	return user, nil
}

func (s *AuthServiceImpl) ResetPassword(user userEntities.PlatformUser) (userEntities.PlatformUser, error) {
	const defaultPass = "qwe123456" // TODO: generate new random password

	if !s.isValidByPasswordPolicy(defaultPass) {
		return user, errors.New("password not valid by policy")
	}

	err := user.SetPasswordHash(s.withSalt(defaultPass))
	if err != nil {
		return user, err
	}

	return user, nil
}

func (s *AuthServiceImpl) Logout(refreshToken string) error {
	user, err := s.repo.SelectUserByRefreshToken(refreshToken)
	if err != nil {
		return err
	} else if user.ID == 0 {
		return errors.New("user not found")
	}

	user.RefreshToken = ""

	return s.repo.UpdateUserWithRefreshToken(user)
}

func (s *AuthServiceImpl) Validate(accessToken string) (claims authEntities.AccessTokenClaims, err error) {
	claims, err = s.verifyAccessToken(s.signingMethod, accessToken, s.accessTokenKey)
	if err != nil {
		return authEntities.AccessTokenClaims{}, err
	}

	return claims, err
}

func (s *AuthServiceImpl) Refresh(token string) (accessToken, refreshToken string, err error) {
	claims, err := s.verifyRefreshToken(s.signingMethod, token, s.refreshTokenKey)
	if err != nil {
		return "", "", err
	}

	if claims.UserID == 0 {
		return "", "", errors.New("missing user id")
	}

	user, err := s.repo.SelectUser(claims.UserID)
	if err != nil {
		return "", "", err
	} else if user.ID == 0 {
		return "", "", errors.New("user not found")
	}

	accessToken, err = s.accessTokenFactory.ProduceAccessToken(user.GetRoleIDs(), user.ID).Sing(s.signingMethod, s.accessTokenKey)
	if err != nil {
		return "", "", err
	}

	refreshToken, err = s.accessTokenFactory.ProduceRefreshToken(user.ID).Sing(s.signingMethod, s.refreshTokenKey)
	if err != nil {
		return "", "", err
	}

	user.RefreshToken = refreshToken
	err = s.repo.UpdateUserWithRefreshToken(user)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthServiceImpl) GetPasswordStrength(password string) (level int, time float64, entropy float64) {
	result := zxcvbn.PasswordStrength(password, []string{})

	return result.Score, result.CrackTime, result.CrackTime
}

func (s *AuthServiceImpl) isValidByPasswordPolicy(password string) bool {
	if len(password) < 8 {
		return false
	}

	result := zxcvbn.PasswordStrength(password, []string{})
	if result.Score <= 1 {
		return false
	}

	return true
}

func (s *AuthServiceImpl) withSalt(password string) string {
	return strings.Join([]string{password, s.salt}, "")
}

func (s *AuthServiceImpl) verifyAccessToken(method *jwt.SigningMethodHMAC, tokenString string, key []byte) (authEntities.AccessTokenClaims, error) {
	var claims authEntities.AccessTokenClaims

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{method.Alg()}))

	if token.Valid {
		return claims, nil
	}

	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return claims, errors.New("token malformed")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return claims, errors.New("invalid signature")
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		return claims, errors.New("token expired")
	default:
		return claims, errors.New("unexpected error")
	}
}

func (s *AuthServiceImpl) verifyRefreshToken(method *jwt.SigningMethodHMAC, tokenString string, key []byte) (authEntities.RefreshTokenClaims, error) {
	var claims authEntities.RefreshTokenClaims

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{method.Alg()}))

	if token.Valid {
		return claims, nil
	}

	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return claims, errors.New("token malformed")
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return claims, errors.New("invalid signature")
	case errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet):
		return claims, errors.New("token expired")
	default:
		return claims, errors.New("unexpected error")
	}
}
