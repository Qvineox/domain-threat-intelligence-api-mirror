package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"github.com/jackc/pgtype"
	"strings"
)

type UsersServiceImpl struct {
	repo         core.IUsersRepo
	passwordSalt string
}

func (s *UsersServiceImpl) CreateUser(login, password, fullName, email string, roleIDs []uint64) (pgtype.UUID, error) {
	if len(password) == 0 || len(login) == 0 {
		return pgtype.UUID{}, errors.New("password or login empty")
	}

	if !s.isValidByPasswordPolicy(password) {
		return pgtype.UUID{}, errors.New("password not valid by policy")
	}

	newUser, err := userEntities.NewPlatformUser(fullName, login, email, strings.Join([]string{password, s.passwordSalt}, ""), true)
	if err != nil {
		return pgtype.UUID{}, err
	}

	err = newUser.SetRoles(roleIDs)
	if err != nil {
		return pgtype.UUID{}, err
	}

	return s.repo.InsertUser(*newUser)
}

func (s *UsersServiceImpl) SaveUser(user userEntities.PlatformUser, roleIDs []uint64) (pgtype.UUID, error) {
	err := user.SetRoles(roleIDs)
	if err != nil {
		return pgtype.UUID{}, err
	}

	return s.repo.UpdateUser(user)
}

func (s *UsersServiceImpl) DeleteUser(uuid pgtype.UUID) error {
	return s.repo.DeleteUser(uuid)
}

func (s *UsersServiceImpl) RetrieveUsers() ([]userEntities.PlatformUser, error) {
	return s.repo.SelectUsers()
}
func (s *UsersServiceImpl) RetrieveUser(uuid pgtype.UUID) (userEntities.PlatformUser, error) {
	return s.repo.SelectUser(uuid)
}

func (s *UsersServiceImpl) RetrieveRoles() ([]userEntities.PlatformUserRole, error) {
	return s.repo.SelectRoles()
}

func (s *UsersServiceImpl) ResetPassword(uuid pgtype.UUID) error {
	//TODO implement me
	return errors.New("not implemented")
}

func (s *UsersServiceImpl) ChangePassword(uuid pgtype.UUID, oldPassword, newPassword string) error {
	user, err := s.RetrieveUser(uuid)
	if err != nil {
		return err
	} else if len(user.Login) == 0 {
		return errors.New("user not found")
	}

	return errors.New("not implemented")
}

func (s *UsersServiceImpl) isValidByPasswordPolicy(password string) bool {

	if len(password) < 8 {
		return false
	}

	return true
}
