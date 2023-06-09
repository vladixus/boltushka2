package main

import (
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"myapp3/iternal/handlers"
)

func main() {
	r := gin.Default()
	//устанавливаем путь для сохраннения личных карточек юзеров
	r.Static("/Storage", "./Storage")
	//надстройки для корректной работы отправки и получения клиенту браузера
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
	//назначить auth группу handler's с токеном bearer
	auth := r.Group("/")

	auth.Use(handlers.AuthMiddleware)
	//забыл пароль
	r.POST("/forgot-password", handlers.ForgotPassword) //ready
	//восстановить пароль, после получения ссылки на мыло
	r.POST("/reset-password", handlers.ResetPassword) //ready
	//Заменить пароль
	auth.POST("/change-password", handlers.ChangePassword) //ready
	//получить данные о карточках из дефолтной билоетки
	r.GET("/library", handlers.GetLibrary) //ready
	// регистрация юзера
	r.POST("/register", handlers.Register) //ready
	//подтверждение почты
	r.GET("/confirm", handlers.Confirm) //ready
	//обновить инфу профиля
	auth.PUT("/profile/update", handlers.Update) //ready
	//получить инфу профиля
	auth.GET("/profile", handlers.Profile) //ready
	//загрузка фото профиля
	auth.POST("/upload-profile-photo", handlers.UploadProfilePhoto) //ready
	//вход
	r.POST("/login", handlers.Login) //ready
	//обновить куки токен юзера
	r.POST("/refresh_token", handlers.Refresh) //ready
	// загрузкить личные карточки в шаблон юзера
	auth.POST("/upload", handlers.Upload) //ready
	//добавить в дефолтную библиотеку изображения и звуки
	auth.POST("/libradd", handlers.LibrAdd) //ready
	//удаление личный карточек
	auth.DELETE("/delete/:id", handlers.Delete) //ready
	//получение карточек по шаблону
	auth.GET("/templates/:template_id/download", handlers.DownloadTemplate) //ready
	//получение шаблонов юзера
	auth.GET("/templates", handlers.GetTemplates) //ready
	//Создать шаблон юзера
	auth.POST("/template", handlers.PostTemplates)
	// узнать какие папки есть в шаблоне
	auth.GET("/folders/:template_id", handlers.GetFolders) //ready
	// создать папку в шаблоне
	auth.POST("/folder/:template_id", handlers.PostFolders)
	//выход
	auth.POST("/logout", handlers.Logout)

	r.Run()
}
