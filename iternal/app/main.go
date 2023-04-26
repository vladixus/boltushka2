package main

import (
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"myapp2/iternal/handlers"
)

func main() {
	r := gin.Default()
	r.Static("/Storage", "./Storage")
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
			return
		}
		c.Next()
	})
	auth := r.Group("/")

	auth.Use(handlers.AuthMiddleware)

	r.POST("/forgot-password", handlers.ForgotPassword) //ready
	r.POST("/reset-password", handlers.ResetPassword)   //ready
	r.GET("/library", handlers.GetLibrary)              //ready

	// Register a new user
	r.POST("/register", handlers.Register) //ready

	r.GET("/confirm", handlers.Confirm) //ready

	auth.PUT("/profile/update", handlers.Update) //ready

	r.POST("/login", handlers.Login) //ready

	r.POST("/refresh_token", handlers.Refresh) //ready

	// Upload Image and Sound
	auth.POST("/upload", handlers.Upload) //ready

	auth.POST("/libradd", handlers.LibrAdd)

	auth.DELETE("/delete/:id", handlers.Delete)

	auth.GET("/templates/:template_id/download", handlers.DownloadTemplate) //ready

	//Get User Templates
	auth.GET("/templates", handlers.GetTemplates) //ready

	// Create User Template_id
	auth.POST("/template", handlers.PostTempaltes)

	// Get Folders
	auth.GET("/folders/:template_id", handlers.GetFolders) //ready
	// Create Folder
	auth.POST("/folder/:template_id", handlers.PostFolders)

	r.Run()
}
