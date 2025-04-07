package main

import (
	"database/sql"
	"os"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog/log"
)

var db *sql.DB

func initDB() {
	var err error

	connStr := os.Getenv("POSTGRES_CONN")
	if connStr == "" {
		log.Fatal().Msg("POSTGRES_CONN environment variable is required")
	}

	rootHost = os.Getenv("ROOT_HOST")
	if rootHost == "" {
		log.Fatal().Msg("ROOT_HOST environment variable is required")
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS hosts (
			host TEXT PRIMARY KEY,
			destination TEXT NOT NULL UNIQUE,
			owner TEXT,
			created TIMESTAMP,
			updated TIMESTAMP,
			updater_id TEXT,
			entry_method TEXT,
			return_type TEXT DEFAULT 'text',
			permissions_string TEXT DEFAULT '[]'  -- New field with empty array default
		)
	`)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create table")
	}

	// Add the permissions_string column if it doesn't exist
	_, err = db.Exec(`
		DO $$
		BEGIN
			IF NOT EXISTS (
				SELECT FROM information_schema.columns
				WHERE table_name = 'hosts' AND column_name = 'permissions_string'
			) THEN
				ALTER TABLE hosts ADD COLUMN permissions_string TEXT DEFAULT '[]';
			END IF;
		END $$;
	`)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to add permissions_string column")
	}
}

func getHostDataByHost(host string) (*HostData, error) {
	row := db.QueryRow("SELECT host, destination, owner, created, updated, updater_id, entry_method, return_type, permissions_string FROM hosts WHERE host = $1", host)
	var data HostData
	err := row.Scan(&data.Host, &data.Destination, &data.Owner, &data.Created, &data.Updated, &data.UpdaterID, &data.EntryMethod, &data.ReturnType, &data.PermissionsString)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func getHostDataByDestination(destination string) (*HostData, error) {
	row := db.QueryRow("SELECT host, destination, owner, created, updated, updater_id, entry_method, return_type, permissions_string FROM hosts WHERE destination = $1", destination)
	var data HostData
	err := row.Scan(&data.Host, &data.Destination, &data.Owner, &data.Created, &data.Updated, &data.UpdaterID, &data.EntryMethod, &data.ReturnType, &data.PermissionsString)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func insertHostData(data HostData) error {
	_, err := db.Exec(
		"INSERT INTO hosts (host, destination, owner, created, updated, updater_id, entry_method, return_type, permissions_string) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		data.Host, data.Destination, data.Owner, data.Created, data.Updated, data.UpdaterID, data.EntryMethod, data.ReturnType, data.PermissionsString,
	)
	return err
}

func updateHostData(data HostData) error {
	_, err := db.Exec(
		"UPDATE hosts SET destination = $1, updated = $2, updater_id = $3, return_type = $4, permissions_string = $5 WHERE host = $6",
		data.Destination, data.Updated, data.UpdaterID, data.ReturnType, data.PermissionsString, data.Host,
	)
	return err
}
