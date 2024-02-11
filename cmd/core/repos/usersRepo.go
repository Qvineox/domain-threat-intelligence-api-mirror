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
	current, err := repo.SelectUser(user.ID)
	if err != nil {
		return err
	} else if current.ID == 0 {
		return errors.New("user not found")
	}

	return repo.Omit("password_hash", "refresh_token").Save(&user).Error
}

func (repo *UsersRepoImpl) DeleteUser(id uint64) (int64, error) {
	query := repo.Delete(&userEntities.PlatformUser{}, id)
	return query.RowsAffected, query.Error
}

func (repo *UsersRepoImpl) SelectUsers() ([]userEntities.PlatformUser, error) {
	var users []userEntities.PlatformUser

	err := repo.Find(&users).Error
	return users, err
}

func (repo *UsersRepoImpl) SelectUser(id uint64) (userEntities.PlatformUser, error) {
	var user userEntities.PlatformUser

	err := repo.Preload("Permissions").Find(&user, id).Error
	return user, err
}

func (repo *UsersRepoImpl) SelectUserByLogin(login string) (userEntities.PlatformUser, error) {
	var user userEntities.PlatformUser

	err := repo.Preload("Permissions").Where("login = ? AND is_active = true", login).Limit(1).Find(&user).Error
	return user, err
}

func (repo *UsersRepoImpl) SelectUserByRefreshToken(token string) (userEntities.PlatformUser, error) {
	var user userEntities.PlatformUser

	err := repo.Preload("Permissions").Where("refresh_token = ? AND is_active = true", token).Limit(1).Find(&user).Error
	return user, err
}

func (repo *UsersRepoImpl) SelectPermissions() ([]userEntities.PlatformUserPermission, error) {
	var permissions []userEntities.PlatformUserPermission

	err := repo.Find(&permissions).Error
	return permissions, err
}

func (repo *UsersRepoImpl) UpdateUserWithPasswordHash(user userEntities.PlatformUser) error {
	if user.ID == 0 {
		return errors.New("user not found")
	}

	return repo.Omit("refresh_token").Save(user).Error
}

func (repo *UsersRepoImpl) UpdateUserWithRefreshToken(user userEntities.PlatformUser) error {
	if user.ID == 0 {
		return errors.New("user not found")
	}

	return repo.Omit("password_hash").Save(user).Error
}
