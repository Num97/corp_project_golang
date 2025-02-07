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

func UpdateDecisionToTrue(db *sql.DB, id int) error {
	// SQL-запрос для обновления поля decision на true
	query := `
		UPDATE corporation_portal.edit_waiting_list
		SET decision = 'true'
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

func AcceptWaitingEditList(db *sql.DB, worker Worker) error {

	er := UpdateDecisionToTrue(db, worker.ID)
	if er != nil {
		log.Fatalf("Failed to update decision: %v", er)
	}

	query := `UPDATE corporation_portal.workers
				SET departament=$1, "position"=$2, surname=$3, first_name=$4, second_name=$5, outside_number=$6, inside_number=$7,
				first_mobile_number=$8, second_mobile_number=$9, email=$10
				WHERE id=$11;`

	_, err := db.Exec(query,
		nullOrString(worker.Department), nullOrString(worker.Position), nullOrString(worker.Surname),
		nullOrString(worker.FirstName), nullOrString(worker.SecondName), nullOrString(worker.OutsideNumber),
		nullOrString(worker.InsideNumber), nullOrString(worker.FirstMobileNumber),
		nullOrString(worker.SecondMobileNumber), nullOrString(worker.Email), worker.ID)

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

func AcceptWaitingEditListAddHandler(c *gin.Context) {
	var worker Worker
	if err := c.BindJSON(&worker); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := AcceptWaitingEditList(db, worker)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data added successfully"})
}

func GetWaitingListUser(db *sql.DB, workerID *int) ([]Worker, error) {
	// Запрос для извлечения данных
	query := `
		SELECT worker_id, position, surname, first_name, second_name, outside_number, inside_number, 
		       first_mobile_number, second_mobile_number, email, department
		FROM corporation_portal.edit_waiting_list
		WHERE decision IS NULL
	`

	// Добавляем условие для фильтрации по worker_id, если он передан
	if workerID != nil {
		query += " AND worker_id = $1"
	}

	// Выполнение запроса
	var rows *sql.Rows
	var err error
	if workerID != nil {
		rows, err = db.Query(query, *workerID)
	} else {
		rows, err = db.Query(query)
	}

	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer rows.Close()

	// Структура, куда будем сохранять результат
	var workers []Worker

	// Сканируем результат в структуру
	for rows.Next() {
		var worker Worker
		err := rows.Scan(
			&worker.ID,
			&worker.Position,
			&worker.Surname,
			&worker.FirstName,
			&worker.SecondName,
			&worker.OutsideNumber,
			&worker.InsideNumber,
			&worker.FirstMobileNumber,
			&worker.SecondMobileNumber,
			&worker.Email,
			&worker.Department,
		)

		if err != nil {
			return nil, fmt.Errorf("error scanning rows: %v", err)
		}

		workers = append(workers, worker)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error with rows iteration: %v", err)
	}

	return workers, nil
}

func WaitingListUserGetHandler(c *gin.Context) {
	// Получаем ID из параметра пути или строки запроса
	workerIDParam := c.Param("id")
	if workerIDParam == "" {
		workerIDParam = c.DefaultQuery("id", "")
	}

	var workerID *int

	// Преобразуем ID в int, если он передан
	if workerIDParam != "" {
		id, err := strconv.Atoi(workerIDParam)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
			return
		}
		workerID = &id
	}

	// Получаем данные из базы данных
	workers, err := GetWaitingListUser(db, workerID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch data"})
		return
	}

	if len(workers) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "No data found"})
		return
	}

	// Возвращаем данные
	c.JSON(http.StatusOK, workers)
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

	// Маршрут для одобрения изменения пользователя
	r.POST("/api/v1/waiting_edit_list_accept_user", AcceptWaitingEditListAddHandler)

	// Маршрут для получения модерации пользователя
	r.GET("/api/v1/waiting_list_user_get/:id", WaitingListUserGetHandler)

	// Маршрут для получения модерации всех пользователей
	r.GET("/api/v1/waiting_list_user_get", WaitingListUserGetHandler)

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
