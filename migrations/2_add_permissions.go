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

	// Add permissions_string column to the hosts table
	_, err = db.Exec("ALTER TABLE hosts ADD COLUMN IF NOT EXISTS permissions_string JSONB DEFAULT '[]'::jsonb")
	if err != nil {
		log.Fatal("Failed to add permissions_string column:", err)
	}

	log.Println("Added permissions_string column to hosts table successfully")
}
