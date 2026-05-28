package service

import "sso-sdk/server/internal/model"

// ItemService 示例服务
type ItemService struct{}

// GetAll 获取所有 Item
func (s *ItemService) GetAll() []model.Item {
	return []model.Item{
		{ID: 1, Name: "example"},
	}
}

// GetByID 根据 ID 获取 Item
func (s *ItemService) GetByID(id int) *model.Item {
	return &model.Item{ID: id, Name: "example"}
}
