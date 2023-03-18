package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"time"
)

var db *sql.DB

type Download struct {
	imageID   int64  `json:"image_id"`
	imageLink string `json:"image_link"`
	soundID   int64  `json:"sound_id"`
	soundLink string `json:"sound_link"`
}

// User represents the user data in the database
type User struct {
	ID               int64     `json:"id"`
	FioParent        string    `json:"fio_parent"`
	FirstName        string    `json:"first_name"`
	LastName         string    `json:"last_name"`
	Age              int       `json:"age"`
	Gender           string    `json:"gender"`
	Email            string    `json:"email"`
	Passwords        string    `json:"passwords"`
	Confirmed        bool      `json:"confirmed"`
	ResetToken       string    `json:"reset_token"`
	ResetTokenExpiry time.Time `json:"reset_token_expiry"`
}

// Image represents the image data in the database
type Image struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	ImageLink string    `json:"image_link"`
	Creation  time.Time `json:"creation_date"`
	UserID    int64     `json:"user_id"`
	SoundID   int64     `json:"sound_id"`
}

// Sound represents the sound data in the database
type Sound struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	SoundLink string `json:"sound_link"`
}

// Template represents the template data in the database
type Template struct {
	ID           int64     `json:"id"`
	TemplateName string    `json:"template_name"`
	Creation     time.Time `json:"creation_date"`
	Color        string    `json:"color"`
	UserID       int64     `json:"user_id"`
	NumOfPkgs    int64     `json:"num_of_packages"`
}

// Folder represents the folder data in the database
type Folder struct {
	ID         int64  `json:"id"`
	FolderName string `json:"folder_name"`
	TemplateId int64  `json:"template_id"`
	//	FolderId   int64  `json:"folder_id"`
}

// Folder represents the folder data in the database
type CardTemplate struct {
	ID         int64     `json:"id"`
	ImageID    int64     `json:"image_id"`
	TemplateId int64     `json:"template_id"`
	FolderID   int64     `json:"folder_id"`
	Dateadd    time.Time `json:"date_add"`
}

func init() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading config file, %s", err)
	}
	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%s dbname=%s sslmode=disable",
		viper.GetString("db.user"), viper.GetString("db.password"),
		viper.GetString("db.host"), viper.GetString("db.port"), viper.GetString("db.dbname"))

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening database, %s", err)
	}
	err = db.Ping()
	if err != nil {
		log.Fatalf("Error connecting to database, %s", err)
	}

	// Создает таблицы, если таковых нет в БД
	//Пользователь
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
	id SERIAL PRIMARY KEY,
	fio_parent TEXT NOT NULL,
	first_name TEXT NOT NULL,
	last_name TEXT NOT NULL,
	age INT NOT NULL,
	gender TEXT NOT NULL,
	email TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	confirm_token TEXT,
	confirmed BOOLEAN DEFAULT false,
	reset_token_expiry TIMESTAMP
)`)
	if err != nil {
		log.Fatalf("Error creating table users, %s", err)
	}
	//Табл Звук
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS sounds (
	id SERIAL PRIMARY KEY,
	name_sound TEXT NOT NULL,
	sound_link TEXT NOT NULL,
	user_id INT NOT NULL REFERENCES users(id)
)`)
	if err != nil {
		log.Fatalf("Error creating table sounds, %s", err)
	}
	//Табл Изображение
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS images (
	id SERIAL PRIMARY KEY,
	name_img TEXT NOT NULL,
	image_link TEXT NOT NULL,
	creation_date TIMESTAMP NOT NULL,
	user_id INT NOT NULL REFERENCES users(id),
	sound_id INT NOT NULL REFERENCES sounds(id)
)`)
	if err != nil {
		log.Fatalf("Error creating table images, %s", err)
	}
	//Табл Шаблон_пользователя
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS templates (
	id SERIAL PRIMARY KEY,
	template_name TEXT NOT NULL,
	creation_date TIMESTAMP NOT NULL,
    color TEXT NOT NULL,
	user_id INT NOT NULL REFERENCES users(id),
	num_of_packages INT NOT NULL
)`)
	if err != nil {
		log.Fatalf("Error creating table templates, %s", err)
	}
	//
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS packages ( 
		id SERIAL PRIMARY KEY, 
		package_name TEXT NOT NULL,
		template_id INT NOT NULL REFERENCES templates(id),
		creation_date TIMESTAMP NOT NULL, 
		user_id INT NOT NULL REFERENCES users(id) )`)
	if err != nil {
		log.Fatalf("Error creating table packages, %s", err)
	}
	//Табл Папка
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS folders (
	id SERIAL PRIMARY KEY,
	folder_name TEXT NOT NULL,
	template_id INT REFERENCES templates(id)
)`)
	if err != nil {
		log.Fatalf("Error creating table folders, %s", err)
	}
	//Табл карточка шаблона
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS cardtemplate (
	id SERIAL PRIMARY KEY,
	image_id INT REFERENCES images(id),
	template_id INT NOT NULL REFERENCES templates(id),
    folder_id INT REFERENCES folders(id),
    dateadd TIMESTAMP NOT NULL
)`)
	if err != nil {
		log.Fatalf("Error creating table folders, %s", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS refresh_tokens (
	id SERIAL PRIMARY KEY,
	token TEXT NOT NULL ,
	user_id INT REFERENCES users(id)
    
)`)
	if err != nil {
		log.Fatalf("Error creating table folders, %s", err)
	}
}

func authMiddleware(c *gin.Context) {
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

	// Retrieve all images and sounds associated with the template ID and user ID
	// You can use the JOIN clause to join the images, sounds, and cardtemplate tables together
	rows, err := db.Query("SELECT images.id as image_id, images.name_img, images.image_link, sounds.id as sound_id, sounds.name_sound, sounds.sound_link FROM images INNER JOIN cardtemplate ON images.id = cardtemplate.image_id INNER JOIN sounds ON images.sound_id = sounds.id INNER JOIN templates ON templates.id = cardtemplate.template_id WHERE templates.user_id = $1 AND cardtemplate.template_id = $2", userID, templateID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving template data"})
		return
	}
	defer rows.Close()

	// Create a slice to hold the file URLs and IDs
	var files []map[string]interface{}

	// Iterate over the rows and add the URLs and IDs to the slice
	for rows.Next() {
		var imageID, soundID int64
		var imageName, imageLink, soundName, soundLink string
		err := rows.Scan(&imageID, &imageName, &imageLink, &soundID, &soundName, &soundLink)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error scanning row"})
			return
		}

		// Add the URLs and IDs to the slice
		file := map[string]interface{}{
			"image_id":   imageID,
			"image_name": imageName,
			"image_link": imageLink,
			"sound_id":   soundID,
			"sound_name": soundName,
			"sound_link": soundLink,
		}
		files = append(files, file)
	}

	rows2, err := db.Query("SELECT folders.id as folder_id FROM folders INNER JOIN cardtemplate ON folders.template_id = cardtemplate.template_id INNER JOIN templates ON cardtemplate.template_id = templates.id WHERE templates.user_id = $1 AND cardtemplate.template_id = $2 group by folders.id", userID, templateID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving template data2"})
		return
	}
	defer rows2.Close()

	// Create a slice to hold the file URLs and IDs
	var folders2 []map[string]interface{}

	// Iterate over the rows and add the URLs and IDs to the slice
	for rows2.Next() {
		var folderID int64
		err := rows2.Scan(&folderID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error scanning row"})
			return
		}

		// Add the URLs and IDs to the slice
		folder := map[string]interface{}{
			"folder_id": folderID,
		}
		folders2 = append(folders2, folder)
	}

	// Set the headers for the response
	c.Header("Content-Type", "application/json")

	// Return the file URLs and IDs as a JSON response
	c.JSON(http.StatusOK, gin.H{"files": files})
	c.JSON(http.StatusOK, gin.H{"folders": folders2})
}

func saveRefreshToken(refreshToken string, userID int) error {
	_, err := db.Exec("INSERT INTO refresh_tokens (token, user_id) VALUES ($1, $2)", refreshToken, userID)
	return err
}
func getRefreshTokenUserID(refreshToken string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT user_id FROM refresh_tokens WHERE token=$1", refreshToken).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func GenerateToken() (string, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SendConfirmationEmail sends a confirmation email to the specified email address with the confirmation link
func SendConfirmationEmail(email, token string) error {
	from := viper.GetString("mail.email")        // your email address
	password := viper.GetString("mail.password") // your email password

	msg := "From: " + from + "\n" +
		"To: " + email + "\n" +
		"Subject: Confirm Your Email Address\n\n" +
		"Please click the following link to confirm your email address:\n\n" +
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
func sendResetLinkEmail(email, link string) error {
	// TODO: Implement email sending logic using a third-party email service or package
	// Example using SMTP package:
	auth := smtp.PlainAuth("", viper.GetString("mail.email"), viper.GetString("mail.password"), "smtp.gmail.com")
	to := []string{email}
	msg := []byte("To: " + email + "\r\n" +
		"Subject: Password Reset Link\r\n" +
		"\r\n" +
		"Please click the following link to reset your password: " + link + "\r\n")
	err := smtp.SendMail("smtp.gmail.com:587", auth, viper.GetString("mail.email"), to, msg)
	if err != nil {
		return err
	}
	return nil
}

// POST /forgot-password
// Send a password reset link to the user's email
func forgotPassword(c *gin.Context) {
	// Get email from the request body
	var email struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the email exists in the database
	var user User
	err := db.QueryRow("SELECT id, email FROM users WHERE email=$1", email.Email).Scan(&user.ID, &user.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Email address not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the database"})
		}
		return
	}

	// Generate a unique token for the password reset link
	resetToken, err := GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating reset token"})
		return
	}

	// Save the reset token and expiration time in the database
	_, err = db.Exec("UPDATE users SET reset_token=$1, reset_token_expiry=$2 WHERE id=$3", resetToken, time.Now().Add(time.Hour*24), user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user data"})
		return
	}

	// Send the password reset link to the user's email
	resetLink := fmt.Sprintf("http://localhost:8080/reset-password?token=%s", resetToken)
	if err := sendResetLinkEmail(user.Email, resetLink); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error sending reset link"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset link sent to your email"})
}

// POST /reset-password
// Reset the user's password with the new password
func resetPassword(c *gin.Context) {
	// Get the reset token from the URL and new password from the request body
	resetToken := c.Query("token")
	var resetData struct {
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.ShouldBindJSON(&resetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the reset token is valid
	var user User
	err := db.QueryRow("SELECT id, reset_token_expiry FROM users WHERE reset_token=$1", resetToken).Scan(&user.ID, &user.ResetTokenExpiry)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Reset token not found or has expired"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the database"})
		}
		return
	}

	// Check if the reset token has expired
	if user.ResetTokenExpiry.Before(time.Now()) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Reset token not found or has expired"})
		return
	}

	// Update the user's password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(resetData.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing new password"})
		return
	}
	_, err = db.Exec("UPDATE users SET password=$1, reset_token=null, reset_token_expiry=null WHERE id=$2", hashedPassword, user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user data"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}

/////////////////////////

func main() {
	r := gin.Default()
	r.Static("/Storage", "./Storage")

	auth := r.Group("/")
	auth2 := r.Group("/")
	// Protected route
	auth.Use(authMiddleware)
	auth2.Use(authMiddleware)
	////////////////////////
	r.POST("/forgot-password", forgotPassword)
	r.POST("/reset-password", resetPassword)
	////////////////////////

	// Register a new user
	r.POST("/register", func(c *gin.Context) {
		var user User
		err := c.ShouldBindJSON(&user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Check for email uniqueness
		var email string
		err = db.QueryRow("SELECT email FROM users WHERE email=$1", user.Email).Scan(&email)
		if err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "такой email уже существует"})
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
		token, err := GenerateToken()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating confirmation token"})
			return
		}

		// Insert user and confirmation token into database
		_, err = db.Exec("INSERT INTO users (fio_parent,first_name, last_name, age, gender, email, password, confirm_token) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", user.FioParent, user.FirstName, user.LastName, user.Age, user.Gender, user.Email, hashedPassword, token)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error inserting user into database"})
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
	})

	r.GET("/confirm", func(c *gin.Context) {
		token := c.Query("token")

		// Find user with matching confirmation token
		var email string
		err := db.QueryRow("SELECT email FROM users WHERE confirm_token=$1", token).Scan(&email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error finding user with matching token"})
			return
		}

		// Mark user as confirmed
		_, err = db.Exec("UPDATE users SET confirmed=true WHERE email=$1", email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error marking user as confirmed"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Thank you for confirming your email"})
	})

	auth.PUT("/profile/update", func(c *gin.Context) {
		// Extract user ID from URL parameter
		id := c.MustGet("id").(int64)

		// Bind request body to a User object
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check if user exists in database
		var email string
		if err := db.QueryRow("SELECT email FROM users WHERE id=$1", id).Scan(&email); err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying database"})
			}
			return
		}

		// Update user's profile information in database
		_, err := db.Exec("UPDATE users SET fio_parent=$1, first_name=$2, last_name=$3, age=$4, gender=$5 WHERE id=$6", user.FioParent, user.FirstName, user.LastName, user.Age, user.Gender, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user profile"})
			return
		}

		c.Status(http.StatusOK)
		c.JSON(http.StatusOK, gin.H{"message": "User profile updated successfully"})
	})

	r.POST("/login", func(c *gin.Context) {
		var user User
		err := c.ShouldBindJSON(&user)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Get user from database
		var (
			id        int
			firstName string
			lastName  string
			email     string
			password  string
			confirmed bool
		)
		err = db.QueryRow("SELECT id, first_name, last_name, email, password, confirmed FROM users WHERE email=$1", user.Email).Scan(&id, &firstName, &lastName, &email, &password, &confirmed)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверная почта или пароль"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка взятия данных из БД"})
			return
		}
		if !confirmed {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Email не подтвержден"})
			return
		}

		// Compare password
		err = bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Passwords))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверная почта или пароль хэш"})
			return
		}

		// Generate access token
		accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":   id,
			"name": firstName + " " + lastName,
			"exp":  time.Now().Add(time.Hour * 1).Unix(),
		})
		accessTokenString, err := accessToken.SignedString([]byte(viper.GetString("server.jwt_secret")))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка входа JWT token"})
			return
		}

		// Generate refresh token
		refreshToken := uuid.NewString()
		err = saveRefreshToken(refreshToken, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения токена"})
			return
		}

		// Set refresh token in cookie
		c.SetCookie("refresh_token", refreshToken, int(time.Hour*24*7), "/", "", false, true)

		// Return access token and success message
		c.JSON(http.StatusOK, gin.H{
			"access_token": accessTokenString,
			"message":      "User loggined",
		})
	})

	r.POST("/refresh_token", func(c *gin.Context) {
		refreshToken, err := c.Cookie("refresh_token")
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token not found"})
			return
		}

		// Get user ID from refresh token
		userID, err := getRefreshTokenUserID(refreshToken)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
			return
		}

		// Generate new access token
		var user User
		err = db.QueryRow("SELECT id, email FROM users WHERE id=$1", userID).Scan(&user.ID, &user.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user from database"})
			return
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":    user.ID,
			"email": user.Email,
			"exp":   time.Now().Add(time.Hour * 1).Unix()})
		tokenString, err := token.SignedString([]byte(viper.GetString("server.jwt_secret")))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating access token"})
			return
		}

		// Set the new access token in the response cookie
		c.SetCookie("access_token", tokenString, 3600, "/", "", false, true)

		c.JSON(http.StatusOK, gin.H{"message": "Access token refreshed"})
	})

	{
		// Upload Image and Sound

		auth.POST("/upload", func(c *gin.Context) {
			// Get sound and image from request
			form, err := c.MultipartForm()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка получения mulptipart запроса"})
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
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ощибка сохранения изображения в папку"})
				return
			}

			// Parse JSON payload
			var template Template
			err = json.Unmarshal([]byte(form.Value["template"][0]), &template)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка парсинга JSON"})
				return
			}

			// Insert sound into database and get its ID
			var soundID int64
			if err := db.QueryRow("INSERT INTO sounds (name_sound, sound_link, user_id) VALUES ($1, $2, $3) RETURNING id", soundFilename, "Storage/Sounds/"+soundFilename, c.MustGet("id").(int64)).Scan(&soundID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу звук БД"})
				return
			}

			// Insert image into database and use the sound ID retrieved above
			var imageID int64
			if err := db.QueryRow("INSERT INTO images (name_img, image_link, creation_date, user_id, sound_id) VALUES ($1, $2, $3, $4, $5) RETURNING id", imageFilename, "Storage/Images/"+imageFilename, time.Now(), c.MustGet("id").(int64), soundID).Scan(&imageID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу изображение БД"})
				return
			}

			// Insert cardtemplate into database using the image and template IDs
			if _, err := db.Exec("INSERT INTO cardtemplate (image_id, template_id,dateadd) VALUES ($1, $2, $3)", imageID, template.ID, time.Now()); err != nil {
				log.Fatal(err)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу карточки шаблона БД"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Изображение с звук успешно загружены"})
		})

		auth.DELETE("/delete/:id", func(c *gin.Context) {
			// Get ID from request
			id, err := strconv.ParseInt(c.Param("id"), 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
				return
			}

			// Delete image and sound from storage
			var imageLink, soundLink string
			if err := db.QueryRow("SELECT images.image_link, sounds.sound_link FROM images INNER JOIN cardtemplate ON images.id = cardtemplate.image_id INNER JOIN sounds ON images.sound_id = sounds.id WHERE images.id = $1", id).Scan(&imageLink, &soundLink); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving image and sound data"})
				return
			}
			if err := os.Remove(imageLink); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting image from storage"})
				return
			}
			if err := os.Remove(soundLink); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting sound from storage"})
				return
			}

			// Get the sound ID from the image table
			var soundID int64
			if err := db.QueryRow("SELECT sound_id FROM images WHERE id = $1", id).Scan(&soundID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving sound ID from database"})
				return
			}

			// Delete sound from database

			// Delete image from database
			if _, err := db.Exec("DELETE FROM cardtemplate WHERE image_id = $1", id); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting cardtemplate from database"})
				return
			}
			if _, err := db.Exec("DELETE FROM images WHERE id = $1", id); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting image from database"})
				return
			}

			if _, err := db.Exec("DELETE FROM sounds WHERE id = $1", soundID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error deleting sound from database"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "Image and sound deleted successfully"})
		})

		auth.GET("/templates/:template_id/download", DownloadTemplate)

		//Get User Templates
		auth.GET("/templates", func(c *gin.Context) {
			rows, err := db.Query("SELECT id, template_name, creation_date,color, user_id,num_of_packages FROM templates WHERE user_id = $1", c.MustGet("id").(int64))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения пользовательских шаблонов из базы данных"})
				return
			}
			defer rows.Close()
			var templates []Template
			for rows.Next() {
				var template Template
				err := rows.Scan(&template.ID, &template.TemplateName, &template.Creation, &template.Color, &template.UserID, &template.NumOfPkgs)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сканирования пользовательских шаблонов из базы данных"})
					return
				}
				templates = append(templates, template)
			}

			c.JSON(http.StatusOK, gin.H{"templates": templates})
		})

		// Create User Template_id
		auth.POST("/template", func(c *gin.Context) {
			var template Template
			err := c.ShouldBindJSON(&template)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка привязки данных JSON к пользовательскому шаблону"})
				return
			}

			row, err := db.Query("INSERT INTO templates (template_name, creation_date, num_of_packages,color, user_id) VALUES ($1, $2, $3, $4, $5)", template.TemplateName, time.Now(), template.NumOfPkgs, template.Color, c.MustGet("id").(int64))
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки пользовательского шаблона в базу данных"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"message": "template has been added"})
			c.JSON(http.StatusOK, gin.H{"Row": row})
		})

		// Get Folders
		auth.GET("/folders/:template_id", func(c *gin.Context) {

			templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
				return
			}

			// Retrieve all images and sounds associated with the template ID
			// You can use the JOIN clause to join the images, sounds, and cardtemplate tables together
			rows, err := db.Query("SELECT id FROM folders WHERE template_id = $1", templateID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving template data"})
				return
			}
			defer rows.Close()

			// Create a slice to hold the file URLs and IDs
			var files []map[string]interface{}

			// Iterate over the rows and add the URLs and IDs to the slice
			for rows.Next() {
				var folderID int64

				err := rows.Scan(&folderID)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Error scanning row"})
					return
				}

				// Add the URLs and IDs to the slice
				file := map[string]interface{}{
					"folder_id": folderID,
				}
				files = append(files, file)
			}

			// Set the headers for the response
			c.Header("Content-Type", "application/json")

			// Return the file URLs and IDs as a JSON response
			c.JSON(http.StatusOK, gin.H{"files": files})
		})

		// Create Folder
		auth.POST("/folder/:template_id", func(c *gin.Context) {

			templateID, err := strconv.ParseInt(c.Param("template_id"), 10, 64)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid template ID"})
				return
			}

			var folder Folder
			err = c.ShouldBindJSON(&folder)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка привязки данных JSON к папке"})
				return
			}
			var folderID int64

			if err := db.QueryRow("INSERT INTO folders (folder_name, template_id) VALUES ($1, $2) RETURNING id", folder.FolderName, templateID).Scan(&folderID); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу папка БД"})
				return
			}

			_, err = db.Exec("INSERT INTO cardtemplate (folder_id, template_id, dateadd) VALUES ($1, $2, $3)", folderID, templateID, time.Now())
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки папки в базу"})
				return
			}

			c.JSON(http.StatusOK, gin.H{"folder": "Folder uploaded"})
		})

	}

	r.Run()
}
