package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/lib/pq"
)

// Структура для обработки запроса на авторизацию
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Структура для ответа с токеном
type LoginResponse struct {
	Token string `json:"token"`
}

type UserInfo struct {
	ID                 int
	FirstName          sql.NullString
	Surname            sql.NullString
	SecondName         sql.NullString
	Department         sql.NullString
	Position           sql.NullString
	OutsideNumber      sql.NullString
	InsideNumber       sql.NullString
	FirstMobileNumber  sql.NullString
	SecondMobileNumber sql.NullString
	Email              sql.NullString
}

type ConfigDB struct {
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	Host     string `json:"dbhost"`
	Port     int    `json:"dbport"`
}

var jwtKey = []byte("DairyComp") // Секретный ключ для подписи токенов

var db *sql.DB

// Инициализация подключения к базе данных
func init() {
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer configFile.Close()

	var config ConfigDB
	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		log.Fatalf("error decoding config file: %v", err)
	}

	// Подключение к базе данных PostgreSQL
	connStr := fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s sslmode=disable",
		config.User, config.Password, config.Host, config.Port, config.DBName)
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
}

func generateJWT(user UserInfo) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":                   user.ID,
		"username":             user.Email.String,
		"firstname":            user.FirstName.String,
		"surname":              user.Surname.String,
		"secondname":           user.SecondName.String,
		"department":           user.Department.String,
		"position":             user.Position.String,
		"outside_number":       user.OutsideNumber.String,
		"inside_number":        user.InsideNumber.String,
		"first_mobile_number":  user.FirstMobileNumber.String,
		"second_mobile_number": user.SecondMobileNumber.String,
		"email":                user.Email.String,
		"exp":                  time.Now().Add(8 * time.Hour).Unix(), // Токен действует 8 часов
	})
	return token.SignedString(jwtKey)
}

func getUserInfo(login string) (UserInfo, error) {
	fmt.Println(login)
	var userInfo UserInfo

	query := `
		SELECT id, first_name, surname, second_name, departament, position, 
		       outside_number, inside_number, first_mobile_number, second_mobile_number, email 
		FROM corporation_portal.workers 
		WHERE email = $1 LIMIT 1`

	err := db.QueryRow(query, login).Scan(
		&userInfo.ID, &userInfo.FirstName, &userInfo.Surname, &userInfo.SecondName,
		&userInfo.Department, &userInfo.Position, &userInfo.OutsideNumber,
		&userInfo.InsideNumber, &userInfo.FirstMobileNumber, &userInfo.SecondMobileNumber, &userInfo.Email,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return UserInfo{}, fmt.Errorf("user not found")
		}
		return UserInfo{}, err
	}

	return userInfo, nil
}

// Эндпоинт для авторизации
func LoginHandler(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Запрос к базе данных для получения хэшированного пароля
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM corporation_portal.users WHERE login = $1", creds.Username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			// Если пользователь не найден
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		} else {
			// Ошибка при выполнении запроса
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
		return
	}

	// Сравнение введённого пароля с хэшем из базы данных
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(creds.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Добыча данных о пользователе
	userinfo, err := getUserInfo(creds.Username)
	if err != nil {
		fmt.Println(err)
	}

	// Генерация JWT токена
	// token, err := generateJWT(creds.Username, userinfo.FirstName, userinfo.Department)
	token, err := generateJWT(userinfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, LoginResponse{Token: token})
}

// Middleware для проверки токена
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing token"})
			c.Abort()
			return
		}

		tokenString := authHeader[len("Bearer "):]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}
