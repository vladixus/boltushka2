package model

import (
	"time"
)

type ResetData struct {
	Password string `json:"password" binding:"required,min=8"`
}

type Email struct {
	Email string `json:"email" binding:"required,email"`
}

type Session struct {
	ID     int64     `json:"id"`
	EnterT time.Time `json:"enterT"`
	ExitT  time.Time `json:"exitT"`
	userID string    `json:"user_id"`
}

type Profile struct {
	FioUser   string `json:"fio_user"`
	Age       int    `json:"age"`
	Gender    string `json:"gender"`
	Email     string `json:"email"`
	PhotoLink string `json:"photo_link"`
}

type Data struct {
	NameSound  string `json:"name_sound"`
	NameImg    string `json:"name_img"`
	SoundLink  string `json:"sound_link"`
	ImageLink  string `json:"image_link"`
	TemplateID int64  `json:"template_id"`
	Category   string `json:"category"`
}

type Download struct {
	imageID   int64  `json:"image_id"`
	imageLink string `json:"image_link"`
	soundID   int64  `json:"sound_id"`
	soundLink string `json:"sound_link"`
}

// User represents the user data in the database
type User struct {
	ID               int64     `json:"id"`
	FioUser          string    `json:"fio_user"`
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
	CategID      int64     `json:"categ_id"`
}

// Folder represents the folder data in the database
type Folder struct {
	ID         int64  `json:"id"`
	FolderName string `json:"folder_name"`
	TemplateId int64  `json:"template_id"`
	//	FolderId   int64  `json:"folder_id"`
}

type CardTemplate struct {
	ID         int64     `json:"id"`
	ImageID    int64     `json:"image_id"`
	TemplateId int64     `json:"template_id"`
	FolderID   int64     `json:"folder_id"`
	Dateadd    time.Time `json:"date_add"`
}

type Library struct {
	ID        int64  `db:"id"`
	Name      string `db:"name"`
	ImageLink string `db:"imageLink"`
	SoundLink string `db:"soundLink"`
}

type Category struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}
