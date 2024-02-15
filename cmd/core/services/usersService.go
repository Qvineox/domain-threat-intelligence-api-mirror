package services

import (
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"math/rand"
	"strings"
)

type UsersServiceImpl struct {
	repo core.IUsersRepo
	auth core.IAuthService
}

func NewUsersServiceImpl(repo core.IUsersRepo, auth core.IAuthService) *UsersServiceImpl {
	return &UsersServiceImpl{repo: repo, auth: auth}
}

func (s *UsersServiceImpl) SaveUser(user userEntities.PlatformUser, permissionIDs []uint64) error {
	err := user.SetPermissions(permissionIDs)
	if err != nil {
		return err
	}

	return s.repo.UpdateUser(user)
}

func (s *UsersServiceImpl) CreateUser(user userEntities.PlatformUser, password string, permissionIDs []uint64) (uint64, error) {
	err := user.SetPermissions(permissionIDs)
	if err != nil {
		return 0, err
	}

	userID, err := s.auth.Register(user.Login, password, user.FullName, user.Email, permissionIDs)
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (s *UsersServiceImpl) DeleteUser(id uint64) (int64, error) {
	return s.repo.DeleteUser(id)
}

func (s *UsersServiceImpl) RetrieveUsers() ([]userEntities.PlatformUser, error) {
	return s.repo.SelectUsers()
}
func (s *UsersServiceImpl) RetrieveUser(id uint64) (userEntities.PlatformUser, error) {
	return s.repo.SelectUser(id)
}

func (s *UsersServiceImpl) RetrievePermissions() ([]userEntities.PlatformUserPermission, error) {
	return s.repo.SelectPermissions()
}

func (s *UsersServiceImpl) RetrievePermissionPresets() []userEntities.PlatformUserRolesPreset {
	return userEntities.DefaultUserPermissionPresets
}

func (s *UsersServiceImpl) ResetPassword(id uint64) error {
	user, err := s.repo.SelectUser(id)
	if err != nil {
		return err
	} else if user.ID == 0 {
		return errors.New("user not found")
	}

	user, err = s.auth.ResetPassword(user, s.generateRandomSolidPassword())

	err = s.repo.UpdateUserWithPasswordHash(user)
	if err != nil {
		return err
	}

	return nil
}

func (s *UsersServiceImpl) ChangePassword(id uint64, oldPassword, newPassword string) error {
	user, err := s.repo.SelectUser(id)
	if err != nil {
		return err
	} else if user.ID == 0 {
		return errors.New("user not found")
	}

	user, err = s.auth.ChangePassword(user, oldPassword, newPassword)
	if err != nil {
		return err
	}

	err = s.repo.UpdateUserWithPasswordHash(user)
	if err != nil {
		return err
	}

	return nil
}

func (s *UsersServiceImpl) isValidByPasswordPolicy(password string) bool {

	if len(password) < 8 {
		return false
	}

	return true
}

func (s *UsersServiceImpl) generateRandomSolidPassword() string {
	var notSolid = true
	var password = ""

	for notSolid {
		runes := make([]string, 12)
		for i := range runes {
			runes[i] = string(letters[rand.Intn(len(letters))])
		}

		password = strings.Join(runes, "")
		notSolid = !s.isValidByPasswordPolicy(password)
	}

	return password
}
