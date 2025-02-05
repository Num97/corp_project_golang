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

func UpdateDecisionToFalse(db *sql.DB, id int) error {
	// SQL-запрос для обновления поля decision на false
	query := `
		UPDATE corporation_portal.edit_waiting_list
		SET decision = 'false'
		WHERE worker_id = $1 AND decision IS NULL;
	`

	// Выполнение запроса
	_, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("error updating decision: %v", err)
	}

	return nil
}

func InsertWaitingEditList(db *sql.DB, worker Worker) error {

	er := UpdateDecisionToFalse(db, worker.ID)
	if er != nil {
		log.Fatalf("Failed to update decision: %v", er)
	}

	query := `INSERT INTO corporation_portal.edit_waiting_list (
        worker_id, position, surname, first_name, second_name, outside_number, inside_number, 
        first_mobile_number, second_mobile_number, email, department)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);`

	_, err := db.Exec(query,
		worker.ID, nullOrString(worker.Position), nullOrString(worker.Surname),
		nullOrString(worker.FirstName), nullOrString(worker.SecondName), nullOrString(worker.OutsideNumber),
		nullOrString(worker.InsideNumber), nullOrString(worker.FirstMobileNumber),
		nullOrString(worker.SecondMobileNumber), nullOrString(worker.Email), nullOrString(worker.Department))

	return err
}

func nullOrString(value sql.NullString) interface{} {
	if value.Valid {
		return value.String
	}
	return nil
}

func WaitingEditListAddHandler(c *gin.Context) {
	var worker Worker
	if err := c.BindJSON(&worker); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := InsertWaitingEditList(db, worker)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data added successfully"})
}

// ожидание модерации для пользователя
func GetWaitingListUser(db *sql.DB, workerID int) (*Worker, error) {
	// Запрос для извлечения данных
	query := `
		SELECT worker_id, position, surname, first_name, second_name, outside_number, inside_number, 
		       first_mobile_number, second_mobile_number, email, department
		FROM corporation_portal.edit_waiting_list
		WHERE worker_id = $1 AND decision IS NULL;
	`

	// Выполнение запроса
	row := db.QueryRow(query, workerID)

	// Структура, куда будем сохранять результат
	var result Worker

	// Сканируем результат в структуру
	err := row.Scan(
		&result.ID,
		&result.Position,
		&result.Surname,
		&result.FirstName,
		&result.SecondName,
		&result.OutsideNumber,
		&result.InsideNumber,
		&result.FirstMobileNumber,
		&result.SecondMobileNumber,
		&result.Email,
		&result.Department,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Если записи нет в базе, возвращаем nil
			return nil, nil
		}
		return nil, fmt.Errorf("error querying database: %v", err)
	}

	return &result, nil
}

func WaitingListUserGetHandler(c *gin.Context) {
	// Получаем ID из URL-параметра
	workerID := c.Param("id")

	// Преобразуем ID в int
	id, err := strconv.Atoi(workerID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	// Получаем данные из базы данных
	workerData, err := GetWaitingListUser(db, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch data"})
		return
	}

	if workerData == nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "No data found for the given ID"})
		return
	}

	// Заворачиваем в массив, даже если это одна запись
	c.JSON(http.StatusOK, []Worker{*workerData})
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

	// Маршрут для напоминания пароля
	r.POST("/api/v1/signup", SignupHandler)

	// Маршрут для добавления на модерацию
	r.POST("/api/v1/waiting_edit_list_add", WaitingEditListAddHandler)

	r.GET("/api/v1/waiting_list_user_get/:id", WaitingListUserGetHandler)

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
