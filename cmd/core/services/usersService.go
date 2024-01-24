package services

import (
	"crypto/sha512"
	"domain_threat_intelligence_api/cmd/core"
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"encoding/hex"
	"errors"
	"github.com/jackc/pgtype"
)

const salt string = "ag23g2gvsadg31w"

type UsersServiceImpl struct {
	repo core.IUsersRepo
}

func (s *UsersServiceImpl) CreateUser(login, password, fullName, email string) (pgtype.UUID, error) {
	if len(password) == 0 || len(login) == 0 {
		return pgtype.UUID{}, errors.New("password or login empty")
	}

	hasher := sha512.New()
	hasher.Write(append([]byte(password), salt...))

	hashedPass := hasher.Sum(nil)

	newUser := userEntities.PlatformUser{
		FullName:     fullName,
		Login:        login,
		PasswordHash: hex.EncodeToString(hashedPass),
		IsActive:     true,
	}

	return s.repo.InsertUser(newUser)
}

func (s *UsersServiceImpl) SaveUser(user userEntities.PlatformUser) (pgtype.UUID, error) {
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
