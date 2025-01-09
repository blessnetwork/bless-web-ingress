package main

import (
	"database/sql"
	"log"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

func main() {
	_ = godotenv.Load() // Ignore error if .env file is not present

	connStr := os.Getenv("POSTGRES_CONN")
	if connStr == "" {
		log.Fatal("POSTGRES_CONN environment variable is required")
	}

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer db.Close()

	_, err = db.Exec("DROP TABLE IF EXISTS hosts")
	if err != nil {
		log.Fatal("Failed to delete table:", err)
	}

	log.Println("Table 'hosts' deleted successfully")
}
