package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

const moderationDir = "./moderation"
const photoDir = "./photo"

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

type Department struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
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

func GetOrInsertUser(db *sql.DB, login string) (AuthData, error) {
	var storedLogin, storedPassword string
	var foundEmail string

	// Запрос для проверки email среди активных работников
	checkEmailQuery := `
	SELECT email
	FROM corporation_portal.workers 
	WHERE active IS TRUE AND email = $1;
	`

	// Выполняем запрос и проверяем наличие email среди активных работников
	err := db.QueryRow(checkEmailQuery, login).Scan(&foundEmail)
	if err == sql.ErrNoRows {
		// Если email не найден среди активных работников
		log.Printf("Пользователь с email %s не найден среди активных работников\n", login)
		// Продолжаем выполнение программы, возвращаем пустую структуру
		return AuthData{}, nil
	} else if err != nil {
		// Обрабатываем другие ошибки при выполнении запроса
		log.Printf("Ошибка при проверке email: %v\n", err)
		// Продолжаем выполнение программы, возвращаем пустую структуру
		return AuthData{}, nil
	}

	// Генерируем новый пароль
	newPassword := GenerateRandomPassword(10)

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Ошибка при хешировании пароля: %v\n", err)
		// Продолжаем выполнение программы, возвращаем пустую структуру
		return AuthData{}, nil
	}

	// Вставляем пользователя с хешированным паролем
	insertQuery := `INSERT INTO corporation_portal.users (login, password) VALUES ($1, $2) 
					ON CONFLICT (login) DO UPDATE SET password=$2 RETURNING login, password;`
	err = db.QueryRow(insertQuery, login, string(hashedPassword)).Scan(&storedLogin, &storedPassword)
	if err != nil {
		log.Printf("Ошибка при вставке нового пользователя: %v\n", err)
		// Продолжаем выполнение программы, возвращаем пустую структуру
		return AuthData{}, nil
	}

	// Возвращаем данные для авторизации
	return AuthData{storedLogin, newPassword, "Данные для авторизации"}, nil
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

func get(id int) []Worker {
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Printf("Error opening config file: %v", err)
		return nil
	}
	defer configFile.Close()

	var config ConfigDB
	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		log.Printf("Error decoding config file: %v", err)
		return nil
	}

	// Формируем SQL-запрос в зависимости от наличия id
	query := "SELECT id, departament, position, surname, first_name, second_name, outside_number, inside_number, first_mobile_number, second_mobile_number, email FROM corporation_portal.workers WHERE active is true"
	if id != 0 {
		query += " AND id = $1"
	}
	query += " ORDER BY id;"

	var rows *sql.Rows
	if id != 0 {
		rows, err = db.Query(query, id)
	} else {
		rows, err = db.Query(query)
	}
	if err != nil {
		log.Printf("Error querying database: %v", err)
		return nil
	}
	defer rows.Close()

	var workers []Worker
	for rows.Next() {
		worker := Worker{}
		err := rows.Scan(&worker.ID, &worker.Department, &worker.Position, &worker.Surname, &worker.FirstName, &worker.SecondName, &worker.OutsideNumber, &worker.InsideNumber, &worker.FirstMobileNumber, &worker.SecondMobileNumber, &worker.Email)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}
		workers = append(workers, worker)
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

func DismissWorker(db *sql.DB, id int) error {
	// SQL-запрос для обновления поля decision на false
	query := `
		UPDATE corporation_portal.workers
		SET active = 'false'
		WHERE id = $1;
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
		log.Printf("Failed to update decision: %v", er)
		return fmt.Errorf("failed to update decision: %v", er)
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
		log.Printf("Failed to update decision: %v", er)
		return fmt.Errorf("failed to update decision: %v", er)
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

func EditWorker(db *sql.DB, worker Worker) error {

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

func EditWorkerHandler(c *gin.Context) {
	var worker Worker
	if err := c.BindJSON(&worker); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := EditWorker(db, worker)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data added successfully"})
}

func RejectWaitingEditListAddHandler(c *gin.Context) {
	var worker Worker
	if err := c.BindJSON(&worker); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := UpdateDecisionToFalse(db, worker.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to insert data"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Data added successfully"})
}

func DismissWorkerHandler(c *gin.Context) {
	var worker Worker
	if err := c.BindJSON(&worker); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	err := DismissWorker(db, worker.ID)
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

// uploadImageModeration загружает изображение в moderationDir и предварительно чистит его
func uploadImageModeration(c *gin.Context) {
	uploadImage(c, moderationDir, true, false) // Чистим только moderationDir перед загрузкой
}

// uploadImagePhoto загружает изображение в photoDir, предварительно чистя и его, и moderationDir
func uploadImagePhoto(c *gin.Context) {
	uploadImage(c, photoDir, true, true) // Чистим photoDir перед загрузкой, затем moderationDir после
}

// uploadImagePhoto загружает изображение в photoDir, предварительно чистя и его
func uploadImagePhotoDirectly(c *gin.Context) {
	uploadImage(c, photoDir, true, false) // Чистим photoDir перед загрузкой
}

// Основная логика загрузки файлов
func uploadImage(c *gin.Context, targetDir string, clearTarget bool, clearModerationAfter bool) {
	workerId := c.PostForm("id")
	if workerId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Worker ID is required"})
		return
	}

	file, handler, err := c.Request.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to get file from form"})
		return
	}
	defer file.Close()

	// Очищаем целевую папку, если требуется
	if clearTarget {
		err = clearOldFiles(targetDir, workerId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to clear target directory: %v", err)})
			return
		}
	}

	// Генерируем путь файла
	fileExt := filepath.Ext(handler.Filename)
	newFileName := workerId + fileExt
	filePath := filepath.Join(targetDir, newFileName)

	// Создаем новый файл
	out, err := os.Create(filePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Unable to create file: %v", err)})
		return
	}
	defer out.Close()

	// Копируем содержимое
	_, err = io.Copy(out, file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Unable to save file: %v", err)})
		return
	}

	// Если нужно, очищаем moderationDir после загрузки в photoDir
	if clearModerationAfter {
		err = clearOldFiles(moderationDir, workerId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to clear moderation directory: %v", err)})
			return
		}
	}

	// Успешный ответ
	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "file": newFileName})
}

func clearOldFiles(directory, workerId string) error {
	files, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %v", directory, err)
	}

	for _, file := range files {
		name := file.Name()
		baseName := strings.TrimSuffix(name, filepath.Ext(name)) // Убираем расширение
		if baseName == workerId {                                // Сравниваем только имя без расширения
			filePath := filepath.Join(directory, name)
			if err := os.Remove(filePath); err != nil {
				return fmt.Errorf("failed to delete file %s: %v", name, err)
			}
		}
	}

	return nil
}

func getImageFromFolder(folder string) gin.HandlerFunc {
	return func(c *gin.Context) {
		workerId := c.Query("id")
		if workerId == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Worker ID is required"})
			return
		}

		// Ищем файл с нужным workerId
		files, err := os.ReadDir(folder)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read directory"})
			return
		}

		// for _, file := range files {
		// 	if strings.HasPrefix(file.Name(), workerId) {
		// 		filePath := filepath.Join(folder, file.Name())
		// 		c.File(filePath) // Отправляем файл
		// 		return
		// 	}
		// }

		for _, file := range files {
			fileName := file.Name()
			fileBaseName := strings.TrimSuffix(fileName, filepath.Ext(fileName)) // Убираем расширение
			if fileBaseName == workerId {
				filePath := filepath.Join(folder, fileName)
				c.File(filePath)
				return
			}
		}

		// Если файл не найден
		c.JSON(http.StatusNotFound, gin.H{"error": "Image not found"})
	}
}

func acceptImage(c *gin.Context) {
	workerId := c.Query("id")
	if workerId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Worker ID is required"})
		return
	}

	// Ищем файл в moderationDir
	filePath, err := findFileByWorkerId(moderationDir, workerId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found in moderationDir"})
		return
	}

	// Очищаем только файлы с этим workerId в photoDir перед копированием
	_, err = clearFilesByWorkerId(photoDir, workerId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear files in photoDir"})
		return
	}

	// Определяем новый путь в photoDir
	newFilePath := filepath.Join(photoDir, filepath.Base(filePath))

	// Копируем файл
	err = copyFile(filePath, newFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to copy file to photoDir"})
		return
	}

	// Удаляем только файлы с этим workerId в moderationDir
	_, err = clearFilesByWorkerId(moderationDir, workerId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete file from moderationDir"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Image accepted successfully", "file": filepath.Base(filePath)})
}

// findFileByWorkerId ищет файл в папке по workerId
func findFileByWorkerId(directory, workerId string) (string, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), workerId) {
			return filepath.Join(directory, file.Name()), nil
		}
	}

	return "", fmt.Errorf("file not found")
}

// copyFile копирует файл из source в destination
func copyFile(source, destination string) error {
	srcFile, err := os.Open(source)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(destination)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// reject image
func rejectImage(c *gin.Context) {
	workerId := c.Query("id")
	if workerId == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Worker ID is required"})
		return
	}

	// Удаляем файлы с workerId в moderationDir
	deleted, err := clearFilesByWorkerId(moderationDir, workerId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to delete files: %v", err)})
		return
	}

	if deleted {
		c.JSON(http.StatusOK, gin.H{"message": "Image rejected and deleted successfully"})
	} else {
		c.JSON(http.StatusNotFound, gin.H{"error": "No files found for this workerId"})
	}
}

func clearFilesByWorkerId(directory, workerId string) (bool, error) {
	files, err := os.ReadDir(directory)
	if err != nil {
		return false, fmt.Errorf("failed to read directory: %v", err)
	}

	deleted := false
	for _, file := range files {
		if strings.HasPrefix(file.Name(), workerId) {
			err := os.Remove(filepath.Join(directory, file.Name()))
			if err != nil {
				return false, fmt.Errorf("failed to delete file %s: %v", file.Name(), err)
			}
			deleted = true
		}
	}

	return deleted, nil
}

func onlyOneWorkerHandler(c *gin.Context) {
	// Получаем id из query-параметров
	idStr := c.Query("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid id"})
		return
	}

	// Получаем данные о работнике
	workerData := get(id)
	if len(workerData) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Worker not found"})
		return
	}

	// Возвращаем данные
	c.Header("Content-Type", "application/json")
	c.Header("Access-Control-Allow-Origin", "*")
	c.JSON(http.StatusOK, workerData) // Возвращаем первого работника (единственного)
}

func getDepartments(db *sql.DB) ([]Department, error) {
	rows, err := db.Query(`
		SELECT DISTINCT departament 
		FROM corporation_portal.workers 
		WHERE active IS NOT FALSE AND departament IS NOT NULL;
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var departments []Department
	id := 1 // Начинаем ID с 1 (можно с 0, если нужно)

	for rows.Next() {
		var d Department
		if err := rows.Scan(&d.Name); err != nil {
			return nil, err
		}
		d.ID = id // Назначаем ID вручную
		id++
		departments = append(departments, d)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return departments, nil
}

func departmentsHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		departments, err := getDepartments(db)
		if err != nil {
			log.Println("Ошибка получения отделов:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось получить отделы"})
			return
		}
		c.JSON(http.StatusOK, departments)
	}
}

func addWorker(c *gin.Context) {
	var worker Worker

	// Декодируем JSON
	if err := c.ShouldBindJSON(&worker); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// SQL-запрос для вставки
	query := `
		INSERT INTO corporation_portal.workers (
			departament, "position", surname, first_name, second_name, 
			outside_number, inside_number, first_mobile_number, second_mobile_number, email, active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true) RETURNING id
	`

	var workerID int
	err := db.QueryRow(query,
		nullOrString(worker.Department),
		nullOrString(worker.Position),
		nullOrString(worker.Surname),
		nullOrString(worker.FirstName),
		nullOrString(worker.SecondName),
		nullOrString(worker.OutsideNumber),
		nullOrString(worker.InsideNumber),
		nullOrString(worker.FirstMobileNumber),
		nullOrString(worker.SecondMobileNumber),
		nullOrString(worker.Email),
	).Scan(&workerID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to insert worker: %v", err)})
		return
	}

	// Отправляем ID на фронт
	c.JSON(http.StatusOK, gin.H{"workerId": workerID})
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

	// Маршрут для изменения данных работника
	r.POST("/api/v1/edit_worker", EditWorkerHandler)

	// Маршрут для одобрения изменения пользователя
	r.POST("/api/v1/waiting_edit_list_reject_user", RejectWaitingEditListAddHandler)

	// Маршрут для увольнения работника
	r.POST("/api/v1/dismiss_worker", DismissWorkerHandler)

	r.POST("/api/v1/upload_image_moderation", uploadImageModeration)

	r.POST("/api/v1/upload_image_photo", uploadImagePhoto)

	r.POST("/api/v1/upload_image_photo_directly", uploadImagePhotoDirectly)

	r.GET("/api/v1/get_image_moderation", getImageFromFolder(moderationDir))

	r.GET("/api/v1/get_image_photo", getImageFromFolder(photoDir))

	r.POST("/api/v1/accept_image", acceptImage)

	r.POST("/api/v1/reject_image", rejectImage)

	// Маршрут для получения модерации пользователя
	r.GET("/api/v1/waiting_list_user_get/:id", WaitingListUserGetHandler)

	// Маршрут для получения модерации всех пользователей
	r.GET("/api/v1/waiting_list_user_get", WaitingListUserGetHandler)

	r.GET("/api/v1/departments", departmentsHandler(db))

	r.POST("/api/v1/add_worker", addWorker)

	// Маршрут только для одного работника
	r.GET("/api/v1/worker", onlyOneWorkerHandler)

	// Маршрут для workers
	r.GET("/api/v1/workers", func(c *gin.Context) {
		jsonData := get(0)
		c.Header("Content-Type", "application/json")
		c.Header("Access-Control-Allow-Origin", "*")
		c.JSON(http.StatusOK, jsonData)
	})

	// Запуск сервера на указанном хосте и порту
	host := config.Host + ":" + strconv.Itoa(config.Port)
	log.Printf("Starting server on %s...", host)
	log.Fatal(r.Run(host))
}
