## RESTful API Web App for get's and post's arasaac cards  📒📗📕
***
## Technologies 💻

-  Golang
-  Gin Framework
-  Viper Configurator
-  PostgreSQL
-  JWT authentication
***
## Tasks:
- [x]  Registration
- [x]  Confirm Email
- [x]  Login
- [x]  Reset Password
- [x]  Update Profile
- [x]  Post / Get Templates
- [x]  Post / Get Folders
- [x]  Get Library cards
- [x]  Adding cards to templates from Library
- [x]  Upload own cards
- [x]  Delete own cards
***
## How to start
- Download all modules from 'go.mod' in terminal `go get -u <GIT_LINK>` or `go get .`
- Download [PostgresSQL](https://www.postgresql.org/download/).
- Make Gmail 2-step verification to get `SMTP_PASSWORD`.
- Create a service in the passwords and applications of your Google account, specifying the 'mail' and device application: 'other'.
- Create in package *iternal* folder *config* and add file *config.yaml*.

```
server:
  jwt_secret: "<TYPE_YOR_SECRET>"
  port: "8080"
db:
  user: "<NAME_OF_USER>"
  password: "<DB_PASSWORD>"
  host: "localhost"
  port: "5432"
  dbname: "<DB_NAME>"
mail:
  email: "<YOUR_SMTP_GMAIL>"
  password: "<YOUR_SMTP_PASSWORD_AUTHENTICATION>"
  ```
***
## Insomina tests
1.  Registration
<details>
<img src="./gitimages/Register.png">
</details>   
2.  Confirm Email
<details>
<img src="./gitimages/Confirm.png">
</details>  
3.  Login
<details>
<img src="./gitimages/Login2.png">
</details> 
4.  Reset Password
<details>
<img src="./gitimages/ResetPassword.png">
</details> 
5.  Update Profile
<details>
<img src="./gitimages/Update.png">
</details> 
6.  Post / Get Templates
<details>
<img src="./gitimages/PostTemp.png">
<img src="./gitimages/GetTemp.png">
</details> 
7.  Post / Get Folders
<details>
<img src="./gitimages/PostFolder.png">
<img src="./gitimages/GetFolders.png">
</details> 
8.  Get Library cards
<details>
<img src="./gitimages/GetLibrary.png">
</details> 
9.  Adding cards to templates from Library
<details>
<img src="./gitimages/AddFromLibrary.png">
</details> 
10.  Upload own cards
<details>
<img src="./gitimages/Upload.png">
</details> 
11.   Delete own cards
<details>
<img src="./gitimages/Delete.png">
</details> 
