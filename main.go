package main

import (
	"cmp"
	"os"
	"strings"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	database "github.com/blessnetwork/bless-web-ingress/db"
)

var (
	cfg appConfig
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
	cfg.dbConn = os.Getenv("POSTGRES_CONN")

	cfg.externalAPIURLs = strings.Split(os.Getenv("EXTERNAL_API_URL"), ",")

	cfg.port = cmp.Or(
		os.Getenv("PORT"),
		DefaultAppPort,
	)
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	h, err := database.Connect("postgres", cfg.dbConn)
	if err != nil {
		log.Fatal().Err(err).Msg("could not connect to the database")
	}

	db, err := database.NewDB(h, true)
	if err != nil {
		log.Fatal().Err(err).Msg("db init failed")
	}
	defer db.Close()

	addr := ":" + cfg.port

	api := newAPI(addr, db)
	api.Start()
}
