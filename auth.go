package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/lib/pq"
)

var db *sql.DB

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
	FirstName  string `json:"firstname"`
	Department string `json:"department"`
}

var jwtKey = []byte("secret_key") // Секретный ключ для подписи токенов

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

// Функция генерации JWT
func generateJWT(username string, firstname string, department string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username":   username,
		"firstname":  firstname,
		"department": department,
		"exp":        time.Now().Add(24 * time.Hour).Unix(), // Токен действует 24 часа
	})
	return token.SignedString(jwtKey)
}

// func getUserInfo(id int) (UserInfo, error) {
// 	rows, err := db.Query("SELECT first_name, departament FROM corporation_portal.workers WHERE id = $1", id)
// 	if err != nil {
// 		fmt.Println(rows)
// 		return UserInfo{}, err
// 	}
// 	defer rows.Close()

// 	// Преобразование данных
// 	userInfo := UserInfo{}
// 	err = rows.Scan(&userInfo.FirstName)
// 	if err != nil {
// 		// Обработка ошибки
// 		return userInfo, err
// 	}

// 	return userInfo, nil
// }

func getUserInfo(login string) (UserInfo, error) {
	rows, err := db.Query("SELECT first_name, departament FROM corporation_portal.workers WHERE email = $1 LIMIT 1", login)
	if err != nil {
		return UserInfo{}, err
	}
	defer rows.Close()

	// Проверка наличия результатов
	if !rows.Next() {
		// Обработка случая, когда результатов нет
		return UserInfo{}, fmt.Errorf("no results found for user %s", login)
	}

	userInfo := UserInfo{}
	err = rows.Scan(&userInfo.FirstName, &userInfo.Department)
	if err != nil {
		// Обработка ошибки
		return userInfo, err
	}

	return userInfo, nil
}

// func getUserInfo(id int) (string, error) {
// 	row := db.QueryRow("SELECT first_name FROM corporation_portal.workers WHERE id = $1", id)
// 	var userName string
// 	err := row.Scan(&userName)
// 	if err != nil {
// 		return "", err
// 	}
// 	return userName, nil
// }

// Эндпоинт для авторизации
func LoginHandler(c *gin.Context) {
	var creds Credentials
	if err := c.BindJSON(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Запрос к базе данных для получения пароля
	var dbPassword string
	err := db.QueryRow("SELECT password FROM corporation_portal.users WHERE login = $1", creds.Username).Scan(&dbPassword)
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

	// Сравнение введённого пароля с паролем из базы данных
	if creds.Password != dbPassword {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Добыча данных о пользователе
	userinfo, err := getUserInfo(creds.Username)
	if err != nil {
		fmt.Println(err)
	}

	// Генерация JWT токена
	token, err := generateJWT(creds.Username, userinfo.FirstName, userinfo.Department)
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
