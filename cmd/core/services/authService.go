package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"github.com/jackc/pgtype"
	"strings"
)

type AuthServiceImpl struct {
	repo core.IUsersRepo
	salt string
}

func NewAuthServiceImpl(repo core.IUsersRepo, salt string) *AuthServiceImpl {
	return &AuthServiceImpl{repo: repo, salt: salt}
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

	err = newUser.SetRoles(roleIDs)
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

	// TODO: generate tokens

	return "", "", nil
}

func (s *AuthServiceImpl) Logout(token string) error {
	//TODO implement me
	panic("implement me")
}

func (s *AuthServiceImpl) Validate(token string) (isValid bool, err error) {
	//TODO implement me
	panic("implement me")
}

func (s *AuthServiceImpl) Refresh(token string) (accessToken, refreshToken string, err error) {
	//TODO implement me
	panic("implement me")
}

func (s *AuthServiceImpl) isValidByPasswordPolicy(password string) bool {

	if len(password) < 8 {
		return false
	}

	return true
}

func (s *AuthServiceImpl) withSalt(password string) string {
	return strings.Join([]string{password, s.salt}, "")
}
