package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/authEntities"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgtype"
	"github.com/nbutton23/zxcvbn-go"
	"log/slog"
	"math/rand"
	"strings"
	"time"
)

type AuthServiceImpl struct {
	repo core.IUsersRepo
	smtp core.ISMTPService

	domain   string
	loginURL string

	salt            string
	accessTokenKey  []byte
	refreshTokenKey []byte

	signingMethod *jwt.SigningMethodHMAC

	accessTokenFactory, refreshTokenFactory *authEntities.TokenFactory
}

func NewAuthServiceImpl(repo core.IUsersRepo, smtp core.ISMTPService, salt, domain, loginURL string) *AuthServiceImpl {
	s := AuthServiceImpl{repo: repo, smtp: smtp, salt: salt, domain: domain, loginURL: loginURL, signingMethod: jwt.SigningMethodHS512}

	s.accessTokenKey, s.refreshTokenKey = generateRandomTokenKeys()

	s.accessTokenFactory = authEntities.NewTokenFactory(domain, "access_token", []string{"users"}, 20*time.Minute)
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

	rows, err := s.repo.InsertUser(*newUser)
	if err != nil {
		return 0, err
	}

	if len(newUser.Email) != 0 {
		var message = "<html>"
		message += fmt.Sprintf("<h2>Добрый день, %s!</h2>", newUser.FullName)
		message += "<h3>Для Вас была создана учетная запись Threat Intel Platform (рабочее название).</h3>"
		message += fmt.Sprintf("<p>Логин: %s.</p>", newUser.Login)
		message += fmt.Sprintf("<p>Пароль: %s.</p>", password)
		message += "</hr>"
		message += fmt.Sprintf("<a href=\"%s\">Ссылка для входа</а>", s.loginURL)
		message += "</html>"

		_ = s.smtp.SendMessage([]string{newUser.Email}, nil, nil, "Добро пожаловать", message)
	}

	return rows, err
}

func (s *AuthServiceImpl) Login(login, password string) (userID uint64, accessToken, refreshToken string, err error) {
	user, err := s.repo.SelectUserByLogin(login)
	if err != nil {
		return 0, "", "", err
	}

	if user.ID == 0 {
		return 0, "", "", errors.New("user not found")
	}

	isValid, err := user.ComparePassword(s.withSalt(password))
	if err != nil {
		return 0, "", "", err
	}

	if !isValid {
		return 0, "", "", errors.New("password invalid")
	}

	accessToken, err = s.accessTokenFactory.ProduceAccessToken(user.GetRoleIDs(), user.ID).Sing(s.signingMethod, s.accessTokenKey)
	if err != nil {
		return 0, "", "", err
	}

	refreshToken, err = s.accessTokenFactory.ProduceRefreshToken(user.ID).Sing(s.signingMethod, s.refreshTokenKey)
	if err != nil {
		return 0, "", "", err
	}

	user.RefreshToken = refreshToken
	err = s.repo.UpdateUserWithRefreshToken(user)
	if err != nil {
		return 0, "", "", err
	}

	return user.ID, accessToken, refreshToken, nil
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

	if len(user.Email) != 0 {
		var message = "<html>"
		message += fmt.Sprintf("<h2>Добрый день, %s!</h2>", user.FullName)
		message += "<h3>Для Вашей учетной записи был изменен пароль.</h3>"
		message += "<p>Чтобы получить новый пароль, обратитесь к администратору.</p>"

		_ = s.smtp.SendMessage([]string{user.Email}, nil, nil, "Ваш пароль был изменен", message)
	}

	return user, nil
}

func (s *AuthServiceImpl) ResetPassword(user userEntities.PlatformUser, newPassword string) (userEntities.PlatformUser, error) {
	err := user.SetPasswordHash(s.withSalt(newPassword))
	if err != nil {
		return user, err
	}

	if len(user.Email) != 0 {
		var message = "<html>"
		message += fmt.Sprintf("<h2>Добрый день, %s!</h2>", user.FullName)
		message += "<h3>Для Вашей учетной записи был сброшен пароль.</h3>"
		message += fmt.Sprintf("<p>Новый пароль: %s.</p>", newPassword)
		message += "</html>"

		_ = s.smtp.SendMessage([]string{user.Email}, nil, nil, "Ваш пароль был сброшен", message)
	}

	return user, nil
}

func (s *AuthServiceImpl) Logout(refreshToken string) (uint64, error) {
	user, err := s.repo.SelectUserByRefreshToken(refreshToken)
	if err != nil {
		return 0, err
	} else if user.ID == 0 {
		return 0, errors.New("user not found")
	}

	user.RefreshToken = ""

	return user.ID, s.repo.UpdateUserWithRefreshToken(user)
}

func (s *AuthServiceImpl) Validate(accessToken string) (claims authEntities.AccessTokenClaims, err error) {
	claims, err = s.verifyAccessToken(s.signingMethod, accessToken, s.accessTokenKey)
	if err != nil {
		return authEntities.AccessTokenClaims{}, err
	}

	return claims, err
}

func (s *AuthServiceImpl) Refresh(refreshToken string) (id uint64, accessToken, newRefreshToken string, err error) {
	claims, err := s.verifyRefreshToken(s.signingMethod, refreshToken, s.refreshTokenKey)
	if err != nil {
		return 0, "", "", err
	}

	if claims.UserID == 0 {
		return 0, "", "", errors.New("missing user id")
	}

	user, err := s.repo.SelectUser(claims.UserID)
	if err != nil {
		return id, "", "", err
	} else if user.ID == 0 {
		return 0, "", "", errors.New("user not found")
	}

	accessToken, err = s.accessTokenFactory.ProduceAccessToken(user.GetRoleIDs(), user.ID).Sing(s.signingMethod, s.accessTokenKey)
	if err != nil {
		return 0, "", "", err
	}

	refreshToken, err = s.refreshTokenFactory.ProduceRefreshToken(user.ID).Sing(s.signingMethod, s.refreshTokenKey)
	if err != nil {
		return 0, "", "", err
	}

	user.RefreshToken = refreshToken
	err = s.repo.UpdateUserWithRefreshToken(user)
	if err != nil {
		return 0, "", "", err
	}

	return user.ID, accessToken, refreshToken, nil
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

	if token != nil && token.Valid {
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

	if token != nil && token.Valid {
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

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

func generateRandomTokenKeys() ([]byte, []byte) {
	slog.Info("generating token keys...")

	accessTokenKey := make([]byte, 16)
	for i := range accessTokenKey {
		accessTokenKey[i] = byte(letters[rand.Intn(len(letters))])
	}

	refreshTokenKey := make([]byte, 16)
	for i := range refreshTokenKey {
		refreshTokenKey[i] = byte(letters[rand.Intn(len(letters))])
	}

	return accessTokenKey, refreshTokenKey
}
