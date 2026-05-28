package main

import (
	"sso-sdk/server/internal/router"
)

func main() {
	r := router.Setup()
	r.Run(":8080")
}
