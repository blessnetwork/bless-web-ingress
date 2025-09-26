package main

import (
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	database "github.com/blessnetwork/bless-web-ingress/db"
)

var (
	cfg appConfig

	db *database.DB
)

type appConfig struct {
	rootHost        string
	rootURL         string
	port            string   // http API port
	dbConn          string   // database holding host data
	externalAPIURLs []string // node URLs
}

func init() {
	registerMetrics()

	_ = godotenv.Load()

	cfg.rootHost = os.Getenv("ROOT_HOST")
	cfg.rootURL = os.Getenv("ROOT_URL")
	cfg.port = os.Getenv("PORT")
	cfg.dbConn = os.Getenv("POSTGRES_CONN")
	cfg.externalAPIURLs = strings.Split(os.Getenv("EXTERNAL_API_URL"), ",")
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	var err error
	db, err = database.Init(cfg.dbConn, true)
	if err != nil {
		log.Fatal().Err(err).Msg("db init failed")
	}
	defer db.Close()

	startAPIServer()
}
