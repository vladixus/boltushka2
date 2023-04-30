package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"log"
	"myapp2/iternal/database"
	"myapp2/iternal/model"
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
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}
	// Verify the JWT token
	tokenString := authHeader[7:]
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Get the secret key from the config file
		secretKey := []byte(viper.GetString("server.jwt_secret"))
		return secretKey, nil
	})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	if !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	// Set the user ID in the context
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
		return
	}
	userID, ok := claims["id"].(float64)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid user ID"})
		return
	}
	c.Set("id", int64(userID))
	c.Next()
}

func DownloadTemplate(c *gin.Context) {
	// Get template ID from request
	templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	// Get user ID from request
	userID, ok := c.Get("id")
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User ID not found in context"})
		return
	}

	files, folders2 := database.DownTempl(c, templateID, userID)

	// устанавливаем хэдер для ответа
	c.Header("Content-Type", "application/json")

	// возвращяем через gin контекст ответ JSON
	c.JSON(http.StatusOK, gin.H{"files": files})
	c.JSON(http.StatusOK, gin.H{"folders": folders2})
}

// Отправка на почту письма с восстановлением пароля (нужно заменить будет ссылку на окно подтверждения с фронта!!!)
func SendConfirmationEmail(email, token string) error {
	from := viper.GetString("mail.email")        // your email address
	password := viper.GetString("mail.password") // your email password

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

///////////////////////////

// sendResetLinkEmail sends the password reset link to the user's email address
func SendResetLinkEmail(email, link string) error {
	// TODO: Implement email sending logic using a third-party email service or package
	// Example using SMTP package:
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

// POST /forgot-password
// Send a password reset link to the user's email
func ForgotPassword(c *gin.Context) {
	// Get email from the request body
	var email model.Email
	if err := c.ShouldBindJSON(&email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the email exists in the database
	var user model.User

	resetToken, user := database.ForgPass(c, user, email)

	// Send the password reset link to the user's email
	resetLink := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", resetToken)
	if err := SendResetLinkEmail(user.Email, resetLink); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending reset link"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset link sent to your email"})
}

// POST /reset-password
// Reset the user's password with the new password
func ResetPassword(c *gin.Context) {
	// Get the reset token from the URL and new password from the request body
	resetToken := c.Query("token")
	var resetData model.ResetData
	if err := c.ShouldBindJSON(&resetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the reset token is valid
	var user model.User
	database.ResPass(user, resetData, resetToken)
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

/////////////////////////

func GetLibrary(c *gin.Context) {
	// Получите все пары файлов из базы данных

	_, pairs := database.GetLibr()

	// Верните массив пар файлов в формате JSON
	c.JSON(http.StatusOK, gin.H{
		"pairs": pairs,
	})
}

func Register(c *gin.Context) {
	var user model.User
	err := c.ShouldBindJSON(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Check for email uniqueness
	err = database.CheckMail(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// check password length
	if len(user.Passwords) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль должен быть больше 8 символов"})
		return
	}

	// hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Passwords), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	// Generate a random confirmation token
	token, err := database.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating confirmation token"})
		return
	}

	// Insert user and confirmation token into database
	err = database.CreateUser(user, hashedPassword, token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Send confirmation email to user
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

	// Find user with matching confirmation token
	// Mark user as confirmed
	database.ConfirmMail(token)

	c.JSON(http.StatusOK, gin.H{"message": "Thank you for confirming your email"})
}

func Update(c *gin.Context) {
	// Extract user ID from URL parameter
	id := c.MustGet("id").(int64)

	// Bind request body to a User object
	var user model.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	database.UpdUser(user, id)

	c.Status(http.StatusOK)
	c.JSON(http.StatusOK, gin.H{"message": "User profile updated successfully"})
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

	// Generate access token
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

	// Generate refresh token
	refreshToken, err := database.SaveRefreshToken(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения токена"})
		return
	}

	// Set refresh token in cookie
	c.SetCookie("refresh_token", refreshToken, int(time.Hour*24*7), "/", "", false, true)

	// Return access token and success message
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessTokenString,
		"message":      "User logged in",
	})
}

func Refresh(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token not found"})
		return
	}

	// Get user ID from refresh token
	userID, err := database.GetRefreshTokenUserID(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Generate new access token
	_, tokenString := database.Refreshing(userID)

	// Set the new access token in the response cookie
	c.SetCookie("access_token", tokenString, 3600, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Access token refreshed"})
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

	database.UploadCard(c, template, soundFilename, imageFilename)

	c.JSON(http.StatusOK, gin.H{"message": "Изображение с звук успешно загружены"})
}

func LibrAdd(c *gin.Context) {
	// Parse JSON payload
	var data struct {
		NameSound  string `json:"name_sound"`
		NameImg    string `json:"name_img"`
		SoundLink  string `json:"sound_link"`
		ImageLink  string `json:"image_link"`
		TemplateID int64  `json:"template_id"`
	}
	if err := c.BindJSON(&data); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка парсинга JSON"})
		return
	}

	// Extract file extensions
	//	soundExt := filepath.Ext(data.SoundLink)
	//	imageExt := filepath.Ext(data.ImageLink)

	// Set name_sound and name_img
	nameSound := filepath.Base(data.SoundLink)
	nameImg := filepath.Base(data.ImageLink)

	database.LibraryAdd(c, nameSound, nameImg)

	c.JSON(http.StatusOK, gin.H{"message": "Изображение со звуком успешно загружены"})
}

func Delete(c *gin.Context) {
	// Get ID from request
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	// Delete image and sound from storage
	database.Del(id)

	c.JSON(http.StatusOK, gin.H{"message": "Image and sound deleted successfully"})
}

func GetTemplates(c *gin.Context) {

	templates := database.GetTemp(c)

	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

func PostTempaltes(c *gin.Context) {
	var template model.Template
	err := c.ShouldBindJSON(&template)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка привязки данных JSON к пользовательскому шаблону"})
		return
	}

	database.PostTempl(template)

	c.JSON(http.StatusOK, gin.H{"message": "template has been added"})
	//	c.JSON(http.StatusOK, gin.H{"Row": row})
}

func GetFolders(c *gin.Context) {
	templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	// Retrieve all images and sounds associated with the template ID
	// You can use the JOIN clause to join the images, sounds, and cardtemplate tables together
	_, files := database.GetFold(templateID)

	// Set the headers for the response
	c.Header("Content-Type", "application/json")

	// Return the file URLs and IDs as a JSON response
	c.JSON(http.StatusOK, gin.H{"files": files})
}

func PostFolders(c *gin.Context) {
	templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
		return
	}

	var folder model.Folder
	err = c.ShouldBindJSON(&folder)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка привязки данных JSON к папке"})
		return
	}

	database.PostFold(templateID, folder)

	c.JSON(http.StatusOK, gin.H{"folder": "Folder uploaded"})
}
