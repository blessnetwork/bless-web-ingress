package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"time"

	ung "github.com/dillonstreator/go-unique-name-generator"
	"github.com/dillonstreator/go-unique-name-generator/dictionaries"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/ksuid"
)

var db *sql.DB
var rootHost string

type HostData struct {
	Host        string    `json:"host"`
	Destination string    `json:"destination"`
	Owner       string    `json:"owner"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated"`
	UpdaterID   string    `json:"updater_id,omitempty"`
	EntryMethod string    `json:"entry_method"`          // New field
	ReturnType  string    `json:"return_type,omitempty"` // New field
}

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
			return_type TEXT DEFAULT 'text'  -- New field with default value
		)
	`)

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create table")
	}
}

func getHostDataByHost(host string) (*HostData, error) {
	row := db.QueryRow("SELECT host, destination, owner, created, updated, updater_id, entry_method, return_type FROM hosts WHERE host = $1", host)
	var data HostData
	err := row.Scan(&data.Host, &data.Destination, &data.Owner, &data.Created, &data.Updated, &data.UpdaterID, &data.EntryMethod, &data.ReturnType)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func getHostDataByDestination(destination string) (*HostData, error) {
	row := db.QueryRow("SELECT host, destination, owner, created, updated, updater_id, entry_method, return_type FROM hosts WHERE destination = $1", destination)
	var data HostData
	err := row.Scan(&data.Host, &data.Destination, &data.Owner, &data.Created, &data.Updated, &data.UpdaterID, &data.EntryMethod, &data.ReturnType)
	if err != nil {
		return nil, err
	}
	return &data, nil
}

func insertHostData(data HostData) error {
	_, err := db.Exec(
		"INSERT INTO hosts (host, destination, owner, created, updated, updater_id, entry_method, return_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		data.Host, data.Destination, data.Owner, data.Created, data.Updated, data.UpdaterID, data.EntryMethod, data.ReturnType,
	)
	return err
}

func updateHostData(data HostData) error {
	_, err := db.Exec(
		"UPDATE hosts SET destination = $1, updated = $2, updater_id = $3, return_type = $4 WHERE host = $5",
		data.Destination, data.Updated, data.UpdaterID, data.ReturnType, data.Host,
	)
	return err
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	data, err := getHostDataByHost(r.Host)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	requestBody := map[string]interface{}{
		"function_id": data.Destination,
		"method":      data.EntryMethod,
		"parameters":  nil,
		"config": map[string]interface{}{
			"permissions":     []interface{}{},
			"env_vars":        []map[string]string{{"name": "BLS_REQUEST_PATH", "value": r.URL.Path}}, // Updated line
			"number_of_nodes": 1,
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		http.Error(w, "Failed to marshal request body", http.StatusInternalServerError)
		return
	}

	externalAPIURL := os.Getenv("EXTERNAL_API_URL")
	if externalAPIURL == "" {
		log.Fatal().Msg("EXTERNAL_API_URL environment variable is required")
	}

	resp, err := http.Post(externalAPIURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to call external API", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "External API call failed", resp.StatusCode)
		return
	}

	switch data.ReturnType {
	case "text":
		w.Header().Set("Content-Type", "text/plain")
	case "json":
		w.Header().Set("Content-Type", "application/json")
	case "html":
		w.Header().Set("Content-Type", "text/html")
	case "raw":
		w.Header().Set("Content-Type", "application/json")
	default:
		w.Header().Set("Content-Type", "application/json")
	}

	w.WriteHeader(resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read response body", http.StatusInternalServerError)
		return
	}

	if data.ReturnType == "raw" {
		if _, err := w.Write(body); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
		}
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		http.Error(w, "Failed to unmarshal response body", http.StatusInternalServerError)
		return
	}

	results, ok := response["results"].([]interface{})
	if !ok || len(results) == 0 {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		return
	}

	result, ok := results[0].(map[string]interface{})
	if !ok {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		return
	}

	stdout, ok := result["result"].(map[string]interface{})["stdout"].(string)
	if !ok {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		return
	}

	if _, err := w.Write([]byte(stdout)); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
	}
}

func handleInsertHost(w http.ResponseWriter, r *http.Request) {
	if r.Host != "localhost:3010" && r.Host != rootHost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var data HostData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if data.Destination == "" || data.EntryMethod == "" {
		http.Error(w, "Destination and EntryMethod are required", http.StatusBadRequest)
		return
	}

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		return
	}

	// Check if the destination is unique
	existingData, err := getHostDataByDestination(data.Destination)
	if err == nil && existingData != nil {
		http.Error(w, "Destination already exists", http.StatusConflict)
		return
	}

	nameGenerator := ung.NewUniqueNameGenerator(
		ung.WithDictionaries(
			[][]string{
				dictionaries.Colors,
				dictionaries.Animals,
				dictionaries.Names,
			},
		),
		ung.WithSeparator("-"),
	)

	rootURL := os.Getenv("ROOT_URL")
	if rootURL == "" {
		log.Fatal().Msg("ROOT_URL environment variable is required")
	}

	data.Host = nameGenerator.Generate() + "-" + data.Destination[len(data.Destination)-8:] + "." + rootURL
	data.Created = time.Now()
	data.Updated = time.Now()
	data.UpdaterID = ksuid.New().String()
	err = insertHostData(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	if r.Host != "localhost:3010" && r.Host != rootHost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var data HostData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if data.Destination == "" || data.UpdaterID == "" {
		http.Error(w, "Destination and UpdaterID are required", http.StatusBadRequest)
		return
	}

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		return
	}

	existingData, err := getHostDataByHost(data.Host)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	if existingData.UpdaterID != data.UpdaterID {
		http.Error(w, "UpdaterID does not match", http.StatusForbidden)
		return
	}

	data.Updated = time.Now()
	err = updateHostData(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	_ = godotenv.Load() // Ignore error if .env file is not present

	initDB()
	defer db.Close()

	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/insert", handleInsertHost)
	http.HandleFunc("/update", handleUpdateHost)

	port := os.Getenv("PORT")
	log.Info().Msgf("Server started on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal().Err(err).Msg("Server failed")
	}
}
