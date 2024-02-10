package repos

import (
	"domain_threat_intelligence_api/cmd/core/entities/userEntities"
	"errors"
	"gorm.io/gorm"
)

type UsersRepoImpl struct {
	*gorm.DB
}

func NewUsersRepoImpl(DB *gorm.DB) *UsersRepoImpl {
	return &UsersRepoImpl{DB: DB}
}

func (repo *UsersRepoImpl) InsertUser(user userEntities.PlatformUser) (uint64, error) {
	err := repo.Create(&user).Error
	return user.ID, err
}

func (repo *UsersRepoImpl) UpdateUser(user userEntities.PlatformUser) error {
	err := repo.Save(&user).Error
	return err
}

func (repo *UsersRepoImpl) DeleteUser(id uint64) (int64, error) {
	query := repo.Delete(&userEntities.PlatformUser{}, id)
	return query.RowsAffected, query.Error
}

func (repo *UsersRepoImpl) SelectUsers() ([]userEntities.PlatformUser, error) {
	var users []userEntities.PlatformUser

	err := repo.Select(&users).Error
	return users, err
}

func (repo *UsersRepoImpl) SelectUser(id uint64) (userEntities.PlatformUser, error) {
	var user userEntities.PlatformUser

	err := repo.Find(&user, id).Error
	return user, err
}

func (repo *UsersRepoImpl) SelectUserByLogin(login string) (userEntities.PlatformUser, error) {
	var user userEntities.PlatformUser

	err := repo.Where("login = ?", login).Find(&user).Error
	return user, err
}

func (repo *UsersRepoImpl) SelectRoles() ([]userEntities.PlatformUserRole, error) {
	var roles []userEntities.PlatformUserRole

	err := repo.Select(&roles).Error
	return roles, err
}

func (repo *UsersRepoImpl) UpdatePasswordHash(id uint64, hash string) error {
	user, err := repo.SelectUser(id)
	if err != nil {
		return err
	}

	if user.ID == 0 {
		return errors.New("user not found")
	}

	user.PasswordHash = hash

	return repo.Save(user).Error
}
