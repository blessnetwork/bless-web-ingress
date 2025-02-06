package main

import (
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
)

var rootHost string

func init() {
	registerMetrics()
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	_ = godotenv.Load()

	initDB()
	defer db.Close()

	startAPIServer()
}
