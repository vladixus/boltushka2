package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"log"
	"myapp2/iternal/model"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

var db *sql.DB

func init() {

	filePath := filepath.Join("iternal", "config")
	viper.SetConfigName("config")
	viper.AddConfigPath(filePath)
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
	//Библиотека
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS library (
	id SERIAL PRIMARY KEY,
	naimenov TEXT NOT NULL,
	imageLink TEXT NOT NULL,
	soundLink TEXT NOT NULL
	
)`)
	if err != nil {
		log.Fatalf("Error creating table users, %s", err)
	}
	//Пользователь
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
	id SERIAL PRIMARY KEY,
	fioUser TEXT NOT NULL,
	age INT NOT NULL,
	gender TEXT NOT NULL,
	email TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	confirm_token TEXT,
	confirmed BOOLEAN DEFAULT false,
	reset_token TEXT,
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

	// Set server directory
	dir := "./library"

	// Get list of image files in server directory
	imageFiles, err := filepath.Glob(dir + "/*.png")
	if err != nil {
		log.Fatal(err)
	}

	// Get list of existing files in database
	existingFiles, err := GetExistingFiles(db)
	if err != nil {
		log.Fatal(err)
	}

	// Iterate through image files
	for _, imageFile := range imageFiles {
		// Get base filename and remove extension
		filename := filepath.Base(imageFile)
		ext := filepath.Ext(filename)
		name := filename[0 : len(filename)-len(ext)]

		// Check if corresponding sound file exists
		soundFile := dir + "/" + name + ".mp3"
		if _, err := os.Stat(soundFile); err != nil {
			if os.IsNotExist(err) {
				// Sound file does not exist
				log.Printf("Sound file for %s not found", name)
				continue
			} else {
				// Error checking for sound file
				log.Fatal(err)
			}
		}

		// Check if file already exists in database
		if _, ok := existingFiles[name]; ok {
			// File already exists in database
			log.Printf("File %s already exists in database", name)
			continue
		}

		// Insert image and sound links to database
		imageLink := "/library/" + name + ".jpg"
		soundLink := "/library/" + name + ".mp3"
		_, err = db.Exec("INSERT INTO Library (naimenov, imageLink, soundLink) VALUES ($1, $2, $3)", name, imageLink, soundLink)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Inserted %s into database", name)
	}

}

func SaveRefreshToken(userID int) (string, error) {
	refreshToken := uuid.NewString()
	_, err := db.Exec("INSERT INTO refresh_tokens (token, user_id) VALUES ($1, $2)", refreshToken, userID)
	return refreshToken, err
}

func GetRefreshTokenUserID(refreshToken string) (int, error) {
	var userID int
	err := db.QueryRow("SELECT user_id FROM refresh_tokens WHERE token=$1", refreshToken).Scan(&userID)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func GetExistingFiles(db *sql.DB) (map[string]bool, error) {
	existingFiles := make(map[string]bool)

	rows, err := db.Query("SELECT naimenov FROM Library")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		existingFiles[name] = true
	}

	return existingFiles, nil
}

func CheckMail(user model.User) error {
	var email string
	err := db.QueryRow("SELECT email FROM users WHERE email=$1", user.Email).Scan(&email)
	if err == nil {
		return fmt.Errorf("такой email уже существует")
	}
	return nil
}

func CreateUser(user model.User, hashedPassword []byte, token string) error {
	_, err := db.Exec("INSERT INTO users (fioUser, age, gender, email, password, confirm_token) VALUES ($1, $2, $3, $4, $5, $6)", user.FioUser, user.Age, user.Gender, user.Email, hashedPassword, token)
	if err != nil {
		return fmt.Errorf("Error inserting user into database")
	}
	return nil
}

func ConfirmMail(token string) error {
	// Find user with matching confirmation token
	var email string
	err := db.QueryRow("SELECT email FROM users WHERE confirm_token=$1", token).Scan(&email)
	if err != nil {
		return fmt.Errorf("Error finding user with matching token: %v", err)
	}

	// Mark user as confirmed
	_, err = db.Exec("UPDATE users SET confirmed=true WHERE email=$1", email)
	if err != nil {
		return fmt.Errorf("Error marking user as confirmed: %v", err)
	}
	return nil
}

func UpdUser(user model.User, id int64) (c *gin.Context) {
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
	_, err := db.Exec("UPDATE users SET fioUser=$1, age=$2, gender=$3 WHERE id=$4", user.FioUser, user.Age, user.Gender, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user profile"})
		return
	}
	return nil
}

func Logg(user model.User, c *gin.Context) (id int, fioUser string, err error) {
	var (
		email     string
		password  string
		confirmed bool
	)
	err = db.QueryRow("SELECT id, fioUser, email, password, confirmed FROM users WHERE email=$1", user.Email).Scan(&id, &fioUser, &email, &password, &confirmed)
	if err != nil {
		if err == sql.ErrNoRows {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Неверная почта или пароль"})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Ошибка взятия данных из БД: %v", err)})
		return
	}
	if !confirmed {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Email не подтвержден"})
		return
	}

	// Compare password
	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Passwords))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Неверная почта или пароль хэш"})
		return
	}

	return id, fioUser, nil
}

func UploadCard(c *gin.Context, template model.Template, soundFilename string, imageFilename string) {
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

}

func Refreshing(userID int) (c *gin.Context, tokenString string) {
	var user model.User
	err := db.QueryRow("SELECT id, email FROM users WHERE id=$1", userID).Scan(&user.ID, &user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error getting user from database"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":    user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 1).Unix()})
	tokenString, err = token.SignedString([]byte(viper.GetString("server.jwt_secret")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating access token"})
		return
	}
	return nil, tokenString
}

func LibraryAdd(nameSound, nameImg string) (c *gin.Context) {
	var data struct {
		NameSound  string `json:"name_sound"`
		NameImg    string `json:"name_img"`
		SoundLink  string `json:"sound_link"`
		ImageLink  string `json:"image_link"`
		TemplateID int64  `json:"template_id"`
	}
	var soundID int64
	if err := db.QueryRow("INSERT INTO sounds (name_sound, sound_link, user_id) VALUES ($1, $2, $3) RETURNING id", nameSound, data.SoundLink, c.MustGet("id").(int64)).Scan(&soundID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу звук БД"})
		return
	}

	// Insert image into database
	var imageID int64
	if err := db.QueryRow("INSERT INTO images (name_img, image_link,creation_date, sound_id,user_id) VALUES ($1, $2, $3, $4, $5) RETURNING id", nameImg, data.ImageLink, time.Now(), soundID, c.MustGet("id").(int64)).Scan(&imageID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу изображение БД"})
		log.Println(err)
		return
	}

	// Insert cardtemplate into database using the image and template IDs
	if _, err := db.Exec("INSERT INTO cardtemplate (image_id, template_id, dateadd) VALUES ($1, $2, $3)", imageID, data.TemplateID, time.Now()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу карточки шаблона БД"})
		return
	}
	return nil
}

func Del(id int64) (c *gin.Context) {
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
	return nil
}

func GetTemp(c *gin.Context) (templates []model.Template) {
	rows, err := db.Query("SELECT id, template_name, creation_date,color, user_id,num_of_packages FROM templates WHERE user_id = $1", c.MustGet("id").(int64))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения пользовательских шаблонов из базы данных"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var template model.Template
		err := rows.Scan(&template.ID, &template.TemplateName, &template.Creation, &template.Color, &template.UserID, &template.NumOfPkgs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сканирования пользовательских шаблонов из базы данных"})
			return
		}
		templates = append(templates, template)
	}
	return templates
}

func DownTempl(c *gin.Context, templateID int64, userID interface{}) (files, folders2 []map[string]interface{}) {
	rows, err := db.Query("SELECT images.id as image_id, images.name_img, images.image_link, sounds.id as sound_id, sounds.name_sound, sounds.sound_link FROM images INNER JOIN cardtemplate ON images.id = cardtemplate.image_id INNER JOIN sounds ON images.sound_id = sounds.id INNER JOIN templates ON templates.id = cardtemplate.template_id WHERE templates.user_id = $1 AND cardtemplate.template_id = $2", userID, templateID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving template data"})
		return
	}
	defer rows.Close()

	// Create a slice to hold the file URLs and IDs
	//	var files []map[string]interface{}

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
	//	var folders2 []map[string]interface{}

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
	return files, folders2
}

func PostTempl(template model.Template) (c *gin.Context) {
	_, err := db.Query("INSERT INTO templates (template_name, creation_date, num_of_packages,color, user_id) VALUES ($1, $2, $3, $4, $5)", template.TemplateName, time.Now(), template.NumOfPkgs, template.Color, c.MustGet("id").(int64))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки пользовательского шаблона в базу данных"})
		return
	}
	return nil
}

func GetFold(templateID int64) (c *gin.Context, files []map[string]interface{}) {
	rows, err := db.Query("SELECT id FROM folders WHERE template_id = $1", templateID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error retrieving template data"})
		return
	}
	defer rows.Close()

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
	return nil, files
}

func PostFold(templateID int64, folder model.Folder) (c *gin.Context) {
	var folderID int64

	if err := db.QueryRow("INSERT INTO folders (folder_name, template_id) VALUES ($1, $2) RETURNING id", folder.FolderName, templateID).Scan(&folderID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки в таблицу папка БД"})
		return
	}

	_, err := db.Exec("INSERT INTO cardtemplate (folder_id, template_id, dateadd) VALUES ($1, $2, $3)", folderID, templateID, time.Now())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка вставки папки в базу"})
		return
	}
	return nil
}

func ForgPass(c *gin.Context, user model.User, email model.Email) (resetToken string, user2 model.User) {

	err := db.QueryRow("SELECT id, email FROM users WHERE email=$1", email.Email).Scan(&user2.ID, &user2.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Email address not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error querying the database"})
		}
		return
	}

	// Generate a unique token for the password reset link
	resetToken, err = GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating reset token"})
		return
	}

	// Save the reset token and expiration time in the database
	_, err = db.Exec("UPDATE users SET reset_token=$1, reset_token_expiry=$2 WHERE id=$3", resetToken, time.Now().Add(time.Hour*24), user2.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating user data"})
		return
	}
	return resetToken, user2
}

func ResPass(user model.User, resetData model.ResetData, resetToken string) (c *gin.Context) {
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
	return c
}

func GetLibr() (c *gin.Context, pairs [][3]string) {
	rows, err := db.Query("SELECT id, naimenov, imageLink, soundLink FROM Library")
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Обойдите все строки результата и создайте массив пар файлов
	pairs = make([][3]string, 0)
	for rows.Next() {
		var id int
		var name, imageLink, soundLink string
		err := rows.Scan(&id, &name, &imageLink, &soundLink)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		pair := [3]string{name, imageLink, soundLink}
		pairs = append(pairs, pair)
	}
	return nil, pairs
}

func GenerateToken() (string, error) {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
