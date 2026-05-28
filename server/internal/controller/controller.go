package controller

import (
	"net/http"
	"strconv"

	"sso-sdk/server/internal/service"

	"github.com/gin-gonic/gin"
)

// ItemController 示例控制器
type ItemController struct {
	svc *service.ItemService
}

// NewItemController 创建控制器实例
func NewItemController() *ItemController {
	return &ItemController{svc: &service.ItemService{}}
}

// List 获取列表
func (c *ItemController) List(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "ok",
		"data": c.svc.GetAll(),
	})
}

// Get 根据 ID 获取
func (c *ItemController) Get(ctx *gin.Context) {
	id, _ := strconv.Atoi(ctx.Param("id"))
	ctx.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "ok",
		"data": c.svc.GetByID(id),
	})
}
