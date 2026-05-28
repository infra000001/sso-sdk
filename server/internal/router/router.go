package router

import (
	"sso-sdk/server/internal/controller"

	"github.com/gin-gonic/gin"
)

// Setup 初始化路由
func Setup() *gin.Engine {
	r := gin.Default()

	itemCtrl := controller.NewItemController()

	api := r.Group("/api/v1")
	{
		api.GET("/items", itemCtrl.List)
		api.GET("/items/:id", itemCtrl.Get)
	}

	return r
}
