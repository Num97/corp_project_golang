package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

type Config struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type ConfigDB struct {
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	Host     string `json:"dbhost"`
	Port     int    `json:"dbport"`
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

	// Подключение к базе данных PostgreSQL
	db, err := sql.Open("postgres", fmt.Sprintf("user=%s password=%s host=%s port=%d dbname=%s sslmode=disable", config.User, config.Password, config.Host, config.Port, config.DBName))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

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
