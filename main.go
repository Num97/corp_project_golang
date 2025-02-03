package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type Config struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type Worker struct {
	ID                 int            `json:"id"`
	Department         sql.NullString `json:"department"`
	Position           sql.NullString `json:"position"`
	Surname            sql.NullString `json:"surname"`
	FirstName          sql.NullString `json:"first_name"`
	SecondName         sql.NullString `json:"second_name"`
	OutsideNumber      sql.NullString `json:"outside_number"`
	InsideNumber       sql.NullString `json:"inside_number"`
	FirstMobileNumber  sql.NullString `json:"first_mobile_number"`
	SecondMobileNumber sql.NullString `json:"second_mobile_number"`
	Email              sql.NullString `json:"email"`
}

type AuthData struct {
	Login    string
	Password string
	Message  string
}

// GenerateRandomPassword создает случайный пароль длиной 10 символов
func GenerateRandomPassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	rand.Seed(time.Now().UnixNano())
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}
	return string(password)
}

// GetOrInsertUser ищет пользователя по login, а если не находит, то добавляет нового
func GetOrInsertUser(db *sql.DB, login string) (AuthData, error) {
	var storedLogin, storedPassword string

	// Проверяем, есть ли такой пользователь
	query := "SELECT login, password FROM corporation_portal.users WHERE login = $1"
	err := db.QueryRow(query, login).Scan(&storedLogin, &storedPassword)
	if err == nil {
		return AuthData{storedLogin, storedPassword, "Напоминание пароля"}, nil // Пользователь найден
	} else if err != sql.ErrNoRows {
		return AuthData{}, fmt.Errorf("ошибка при запросе к БД: %v", err)
	}

	// Если пользователь не найден, создаем нового
	newPassword := GenerateRandomPassword(10)
	insertQuery := "INSERT INTO corporation_portal.users (login, password) VALUES ($1, $2) RETURNING login, password"
	err = db.QueryRow(insertQuery, login, newPassword).Scan(&storedLogin, &storedPassword)
	if err != nil {
		return AuthData{}, fmt.Errorf("ошибка при вставке нового пользователя: %v", err)
	}

	return AuthData{storedLogin, storedPassword, "Данные для авторизации"}, nil
}

func SignupHandler(c *gin.Context) {
	var request struct {
		Login string `json:"login"`
	}

	if err := c.BindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	authData, err := GetOrInsertUser(db, request.Login)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	config, err := LoadConfig("config.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load SMTP configuration"})
		log.Printf("Error loading config: %v", err)
		return
	}

	mailer := NewMailer(config)

	err = mailer.SendMail(request.Login, authData.Login, authData.Password)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send email"})
		return
	}

	c.JSON(http.StatusOK, authData)
}

func get() []Worker {
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

	rows, err := db.Query("SELECT id, departament, position, surname, first_name, second_name, outside_number, inside_number, first_mobile_number, second_mobile_number, email FROM corporation_portal.workers;")
	if err != nil {
		log.Fatal(err)
	}

	var workers []Worker
	for rows.Next() {
		worker := Worker{}
		err := rows.Scan(&worker.ID, &worker.Department, &worker.Position, &worker.Surname, &worker.FirstName, &worker.SecondName, &worker.OutsideNumber, &worker.InsideNumber, &worker.FirstMobileNumber, &worker.SecondMobileNumber, &worker.Email)
		if err != nil {
			log.Fatal(err)
		} else {
			workers = append(workers, worker)
		}
	}
	return workers
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}

func main() {
	// Чтение конфигурационного файла
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer configFile.Close()

	var config Config
	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		log.Fatalf("error decoding config file: %v", err)
	}

	// Создаём маршрутизатор gin
	r := gin.Default()

	r.Use(CORSMiddleware())

	// Маршрут для авторизации
	r.POST("/api/v1/login", LoginHandler)

	r.POST("/api/v1/signup", SignupHandler)

	// Маршрут для workers
	r.GET("/api/v1/workers", func(c *gin.Context) {
		jsonData := get()
		c.Header("Content-Type", "application/json")
		c.Header("Access-Control-Allow-Origin", "*")
		c.JSON(http.StatusOK, jsonData)
	})

	// Запуск сервера на указанном хосте и порту
	host := config.Host + ":" + strconv.Itoa(config.Port)
	log.Printf("Starting server on %s...", host)
	log.Fatal(r.Run(host))
}
