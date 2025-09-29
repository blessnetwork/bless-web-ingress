package db

import (
	"database/sql"
	"errors"
	"fmt"

	_ "github.com/lib/pq"

	"github.com/blessnetwork/bless-web-ingress/ingress"
)

type DB struct {
	*sql.DB
}

func Connect(driverName string, dbconn string) (*sql.DB, error) {

	if dbconn == "" {
		return nil, errors.New("database connection string is required")
	}

	db, err := sql.Open(driverName, dbconn)
	if err != nil {
		return nil, fmt.Errorf("could not connect to the database: %w", err)
	}

	return db, nil
}

func NewDB(db *sql.DB, initTables bool) (*DB, error) {

	out := &DB{
		DB: db,
	}

	if !initTables {
		return out, nil
	}

	err := out.InitTable()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize tables: %w", err)
	}

	return out, nil
}

func (db *DB) InitTable() error {

	_, err := db.Exec(`
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
		return fmt.Errorf("could not create table: %w", err)
	}

	// Add the permissions_string column if it doesn't exist
	// _, err = db.Exec(`
	// 	DO $$
	// 	BEGIN
	// 		IF NOT EXISTS (
	// 			SELECT FROM information_schema.columns
	// 			WHERE table_name = 'hosts' AND column_name = 'permissions_string'
	// 		) THEN
	// 			ALTER TABLE hosts ADD COLUMN permissions_string TEXT DEFAULT '[]';
	// 		END IF;
	// 	END $$;
	// `)
	// if err != nil {
	// 	return fmt.Errorf("could not add permissions column: %w", err)
	// }

	return nil
}

func (db *DB) GetHostDataByHost(host string) (*ingress.Host, error) {

	row := db.QueryRow("SELECT host, destination, owner, created, updated, updater_id, entry_method, return_type, permissions_string FROM hosts WHERE host = $1", host)

	var data ingress.Host
	err := row.Scan(&data.Host, &data.Destination, &data.Owner, &data.Created, &data.Updated, &data.UpdaterID, &data.EntryMethod, &data.ReturnType, &data.PermissionsString)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func (db *DB) GetHostDataByDestination(destination string) (*ingress.Host, error) {

	row := db.QueryRow("SELECT host, destination, owner, created, updated, updater_id, entry_method, return_type, permissions_string FROM hosts WHERE destination = $1", destination)

	var data ingress.Host
	err := row.Scan(&data.Host, &data.Destination, &data.Owner, &data.Created, &data.Updated, &data.UpdaterID, &data.EntryMethod, &data.ReturnType, &data.PermissionsString)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func (db *DB) InsertHostData(host ingress.Host) error {

	_, err := db.Exec(
		"INSERT INTO hosts (host, destination, owner, created, updated, updater_id, entry_method, return_type, permissions_string) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		host.Host,
		host.Destination,
		host.Owner,
		host.Created,
		host.Updated,
		host.UpdaterID,
		host.EntryMethod,
		host.ReturnType,
		host.PermissionsString,
	)
	return err
}

func (db *DB) UpdateHostData(host ingress.Host) error {

	_, err := db.Exec(
		"UPDATE hosts SET destination = $1, updated = $2, updater_id = $3, return_type = $4, permissions_string = $5 WHERE host = $6",
		host.Destination,
		host.Updated,
		host.UpdaterID,
		host.ReturnType,
		host.PermissionsString,
		host.Host,
	)
	return err
}
