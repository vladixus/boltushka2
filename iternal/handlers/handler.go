package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"log"
	"myapp3/iternal/database"
	"myapp3/iternal/model"
	"net/http"
	"net/smtp"
	"path/filepath"
	"strconv"
	"time"
)

//middleware авторизация
func AuthMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Отсутствует header авторизации"})
		return
	}
	// Проверка JWT токена
	tokenString := authHeader[7:]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Метод проверки подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Берем секретный ключ от токена с конфига
		secretKey := []byte(viper.GetString("server.jwt_secret"))
		return secretKey, nil
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "невалидный token"})
		return
	}
	// Установка id пользователя в контекст
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "недействительные заявки на токен"})
		return
	}
	userID, ok := claims["id"].(float64)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "неверный ID пользователя"})
		return
	}
	c.Set("id", int64(userID))
	c.Next()
}

func DownloadTemplate(c *gin.Context) {
	// Получение id из запроса
	templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "неверный идентификатор шаблона"})
		return
	}

	// Получение id из запроса
	userID, ok := c.Get("id")
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ID пользователя не найдено из контекста движка gin"})
		return
	}

	files, folders, err := database.DownTempl(c, templateID, userID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// устанавливаем хэдер для ответа
	c.Header("Content-Type", "application/json")

	// возвращяем через gin контекст ответ JSON
	c.JSON(http.StatusOK, gin.H{"files": files})
	c.JSON(http.StatusOK, gin.H{"folders": folders})
}

// Отправка на почту письма с восстановлением пароля (нужно заменить будет ссылку на окно подтверждения с фронта!!!)
func SendConfirmationEmail(email, token string) error {
	from := viper.GetString("mail.email")        // ваша почта
	password := viper.GetString("mail.password") // ваш пароль от этой почты

	msg := "От: " + from + "\n" +
		"Кому: " + email + "\n" +
		"Тема: Подтвердите ваш адрес\n\n" +
		"Пожалуйста, перейдите по ссылке для подтверждения вашей почты:\n\n" +
		"http://localhost:8080/confirm?token=" + token

	err := smtp.SendMail("smtp.gmail.com:587",
		smtp.PlainAuth("", from, password, "smtp.gmail.com"),
		from, []string{email}, []byte(msg))

	if err != nil {
		return err
	}
	return nil
}

// sendResetLinkEmail отправляет ссылку для сброса пароля на адрес электронной почты пользователя.
func SendResetLinkEmail(email, link string) error {
	// TODO: Implement email sending logic using a third-party email service or package
	auth := smtp.PlainAuth("", viper.GetString("mail.email"), viper.GetString("mail.password"), "smtp.gmail.com")
	to := []string{email}
	msg := []byte("To: " + email + "\r\n" +
		"Восстановление пароля: Ссылка на восстановление пароля\r\n" +
		"\r\n" +
		"Пожалуйста, перейдите по ссылке, чтобы восстановить доступ к аккаунту: " + link + "\r\n")
	err := smtp.SendMail("smtp.gmail.com:587", auth, viper.GetString("mail.email"), to, msg)
	if err != nil {
		return err
	}
	return nil
}

// Отправить ссылку для сброса пароля на электронную почту пользователя
func ForgotPassword(c *gin.Context) {
	// Получить электронную почту из тела запроса
	var email model.Email
	if err := c.ShouldBindJSON(&email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Проверка, существует ли электронная почта в БД
	var user model.User
	resetToken, user, err := database.ForgPass(c, email)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Отправить ссылку для сброса пароля на электронную почту пользователя
	resetLink := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", resetToken)
	if err := SendResetLinkEmail(user.Email, resetLink); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка отправки ссылки на почту"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ссылка на изменение пароля отправлена на вашу почту"})
}

// Сброс пароля пользователя с новым паролем
func ResetPassword(c *gin.Context) {
	// Получите токен сброса из URL-адреса и новый пароль из тела запроса.
	resetToken := c.Query("token")
	var resetData model.ResetData
	if err := c.ShouldBindJSON(&resetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the reset token is valid
	var user model.User
	err := database.ResPass(c, user, resetData, resetToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно сменен"})
}

// Изменение пароля
func ChangePassword(c *gin.Context) {
	// Получите данных.
	var resetData model.ResetData
	if err := c.ShouldBindJSON(&resetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Обновить данные в БД
	err := database.ChangPass(c, resetData)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Пароль успешно сменен"})
}

func GetLibrary(c *gin.Context) {
	// Получите все пары файлов из базы данных

	err, pairs := database.GetLibr(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err})
		return
	}

	// Верните массив пар файлов в формате JSON
	c.JSON(http.StatusOK, gin.H{
		"pairs": pairs,
	})
}

func Register(c *gin.Context) {
	var user model.User
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusNotAcceptable, gin.H{"error": err.Error()})
		return
	}
	// Check for email uniqueness
	err = database.CheckMail(user)
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}

	// Проверка длины пароля
	if len(user.Passwords) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль должен быть больше 8 символов"})
		return
	}

	// Хэш-пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Passwords), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка хэширование пароля"})
		return
	}

	// Создать случайный токен подтверждения
	token, err := database.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка генерации токена подтверждения"})
		return
	}

	//Вставить пользователя и токен подтверждения в базу данных
	err = database.CreateUser(user, hashedPassword, token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Отправить письмо с подтверждением пользователю
	err = SendConfirmationEmail(user.Email, token)
	if err != nil {
		log.Fatal(err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending confirmation email"})
		return
	}

	c.Status(http.StatusCreated)
	c.JSON(http.StatusOK, gin.H{"message": "Регистрация завершена. Пожалуйста, подтвердите свой email"})
}

func Confirm(c *gin.Context) {
	token := c.Query("token")

	// Найти пользователя с соответствующим токеном подтверждения
	// Отметить пользователя как подтвержденного
	err := database.ConfirmMail(token)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Спасибо за подтверждение регистрации"})
}

func Profile(c *gin.Context) {
	var user model.Profile

	user, err := database.Profile(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"User": user})
}

func Update(c *gin.Context) {
	id := c.MustGet("id").(int64)

	var user model.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := database.UpdUser(c, user, id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"message": "Ппофиль пользователя обновлен"})
}

func Login(c *gin.Context) {
	var user model.User
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user from database
	id, fioUser, err := database.Logg(user, c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Генерация access token
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":   id,
		"name": fioUser,
		"exp":  time.Now().Add(time.Hour * 1).Unix(),
	})
	accessTokenString, err := accessToken.SignedString([]byte(viper.GetString("server.jwt_secret")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка входа JWT token"})
		return
	}

	// Генерацифя refresh token
	refreshToken, err := database.SaveRefreshToken(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения токена"})
		return
	}

	// Установка рефреш токена в куки
	c.SetCookie("refresh_token", refreshToken, int(time.Hour*24*7), "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessTokenString,
		"message":      "User logged in",
	})
	fmt.Println(id)
}

func Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token не найден"})
		return
	}

	// Get user ID from refresh token
	userID, err := database.GetRefreshTokenUserID(refreshToken)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Неверный refresh token"})
		return
	}

	// Generate new access token
	_, tokenString := database.Refreshing(userID)

	// Set the new access token in the response cookie
	c.SetCookie("access_token", tokenString, 3600, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Access token обновлен"})
}

func Upload(c *gin.Context) {
	// Get sound and image from request
	form, err := c.MultipartForm()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка получения multipart запроса"})
		return
	}
	sound, err := form.File["sound"][0].Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка получения файла звука с запроса"})
		return
	}
	defer sound.Close()
	image, err := form.File["image"][0].Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка получения файла изображения с запроса"})
		return
	}
	defer image.Close()

	// Save sound and image to Storage/Sounds and Storage/Images folder
	soundFilename := form.File["sound"][0].Filename
	err = c.SaveUploadedFile(form.File["sound"][0], "Storage/Sounds/"+soundFilename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения звука в папку"})
		return
	}
	imageFilename := form.File["image"][0].Filename
	err = c.SaveUploadedFile(form.File["image"][0], "Storage/Images/"+imageFilename)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения изображения в папку"})
		return
	}

	// Parse JSON payload
	var template model.Template
	err = json.Unmarshal([]byte(form.Value["template"][0]), &template)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка парсинга JSON"})
		return
	}

	err = database.UploadCard(c, template, soundFilename, imageFilename)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Изображение с звук успешно загружены"})
}

func LibrAdd(c *gin.Context) {
	// Parse JSON payload
	var data model.Data
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка парсинга JSON"})
		fmt.Println(err)
		return
	}

	// Extract file extensions
	//	soundExt := filepath.Ext(data.SoundLink)
	//	imageExt := filepath.Ext(data.ImageLink)

	// Set name_sound and name_img
	data.NameSound = filepath.Base(data.SoundLink)
	data.NameImg = filepath.Base(data.ImageLink)

	err := database.LibraryAdd(c, data)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Изображение со звуком успешно загружены"})
}

func Delete(c *gin.Context) {
	// Get ID from request
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID"})
		return
	}

	// Удаление из БД
	err = database.Del(c, id)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Изображение и звук удалены успешно"})
}

func GetTemplates(c *gin.Context) {

	templates, err := database.GetTemp(c)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

func PostTemplates(c *gin.Context) {
	var template model.Template
	err := c.ShouldBindJSON(&template)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка привязки данных JSON к пользовательскому шаблону"})
		return
	}

	err = database.PostTempl(template, c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка создания шаблона пользователя"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Шаблон добавлен успешно"})
	//	c.JSON(http.StatusOK, gin.H{"Row": row})
}

func GetFolders(c *gin.Context) {
	templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID шаблона"})
		return
	}

	files, err := database.GetFold(c, templateID)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set the headers for the response
	c.Header("Content-Type", "application/json")

	c.JSON(http.StatusOK, gin.H{"files": files})
}

func PostFolders(c *gin.Context) {
	templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID шаблона"})
		return
	}

	var folder model.Folder
	err = c.ShouldBindJSON(&folder)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка привязки данных JSON к папке"})
		return
	}

	err = database.PostFold(c, templateID, folder)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"folder": "Папка загружена"})
}

func Logout(c *gin.Context) {
	//	userID, err := c.MustGet("id").(int64)
	//	if err != false {
	//		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Неверный refresh token"})
	//		return
	//	}
	// После получения ID пользователя, можно удалить токен обновления из базы данных или установить его срок действия на прошедшую дату

	// Удаляем токен обновления из базы данных
	err2 := database.DeleteRefreshToken(c)
	if err2 != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Ошибка удаления токена обновления"})
		return
	}

	// Удаляем куки с токеном обновления
	c.SetCookie("refresh_token", "", -1, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Успешный выход из аккаунта"})
}

func UploadProfilePhoto(c *gin.Context) {
	// Взять фото из запроса
	file, err := c.FormFile("photo")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get profile photo from the request"})
		return
	}

	// Сохраняем фото на сервак
	photoPath := "Storage/profile-photos/" + file.Filename
	err = c.SaveUploadedFile(file, photoPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save the profile photo on the server"})
		return
	}

	// Get the user ID from the request (assuming it's stored in the context)
	userID := c.MustGet("id").(int64)
	photoLink := "/profile-photos/" + file.Filename

	err = database.SaveProfileLinkPhoto(c, userID, photoLink)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Фото загружено"})
}
