package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
)

type UsersServiceImpl struct {
	repo         core.IUsersRepo
	passwordSalt string
}

func NewUsersServiceImpl(repo core.IUsersRepo) *UsersServiceImpl {
	return &UsersServiceImpl{repo: repo}
}

func (s *UsersServiceImpl) SaveUser(user userEntities.PlatformUser, roleIDs []uint64) error {
	err := user.SetRoles(roleIDs)
	if err != nil {
		return err
	}

	return s.repo.UpdateUser(user)
}

func (s *UsersServiceImpl) DeleteUser(id uint64) error {
	return s.repo.DeleteUser(id)
}

func (s *UsersServiceImpl) RetrieveUsers() ([]userEntities.PlatformUser, error) {
	return s.repo.SelectUsers()
}
func (s *UsersServiceImpl) RetrieveUser(id uint64) (userEntities.PlatformUser, error) {
	return s.repo.SelectUser(id)
}

func (s *UsersServiceImpl) RetrieveRoles() ([]userEntities.PlatformUserRole, error) {
	return s.repo.SelectRoles()
}

func (s *UsersServiceImpl) ResetPassword(id uint64) error {
	//TODO implement me
	return errors.New("not implemented")
}

func (s *UsersServiceImpl) ChangePassword(id uint64, oldPassword, newPassword string) error {
	user, err := s.RetrieveUser(id)
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
