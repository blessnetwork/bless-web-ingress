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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/ksuid"
)

var (
	db       *sql.DB
	rootHost string
	reqCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Number of HTTP requests",
		},
		[]string{"path"},
	)
	reqDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"path"},
	)
)

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

func init() {
	prometheus.MustRegister(reqCount)
	prometheus.MustRegister(reqDuration)
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
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msgf("Received request for host: %s, path: %s", r.Host, r.URL.Path) // Logging request

	data, err := getHostDataByHost(r.Host)
	if err != nil {
		http.NotFound(w, r)
		log.Error().Err(err).Msg("Host not found") // Logging error
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
		log.Error().Err(err).Msg("Failed to marshal request body") // Logging error
		return
	}

	externalAPIURL := os.Getenv("EXTERNAL_API_URL")
	if externalAPIURL == "" {
		log.Fatal().Msg("EXTERNAL_API_URL environment variable is required")
	}

	resp, err := http.Post(externalAPIURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		http.Error(w, "Failed to call external API", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to call external API") // Logging error
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "External API call failed", resp.StatusCode)
		log.Error().Msgf("External API call failed with status: %d", resp.StatusCode) // Logging error
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
		log.Error().Err(err).Msg("Failed to read response body") // Logging error
		return
	}

	if data.ReturnType == "raw" {
		if _, err := w.Write(body); err != nil {
			http.Error(w, "Failed to write response", http.StatusInternalServerError)
			log.Error().Err(err).Msg("Failed to write response") // Logging error
		}
		log.Info().Msg("Response sent successfully") // Logging success
		return
	}

	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		http.Error(w, "Failed to unmarshal response body", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to unmarshal response body") // Logging error
		return
	}

	results, ok := response["results"].([]interface{})
	if !ok || len(results) == 0 {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		log.Error().Msg("Invalid response format") // Logging error
		return
	}

	result, ok := results[0].(map[string]interface{})
	if !ok {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		log.Error().Msg("Invalid response format") // Logging error
		return
	}

	stdout, ok := result["result"].(map[string]interface{})["stdout"].(string)
	if !ok {
		http.Error(w, "Invalid response format", http.StatusInternalServerError)
		log.Error().Msg("Invalid response format") // Logging error
		return
	}

	if _, err := w.Write([]byte(stdout)); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to write response") // Logging error
	}
	log.Info().Msg("Response sent successfully") // Logging success
}

func handleInsertHost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received insert host request") // Logging request

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010" // Default port if not set
	}

	if r.Host != "localhost:"+port && r.Host != rootHost {
		handleRequest(w, r) // Pass to handleRequest
		return
	}

	var data HostData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Err(err).Msg("Failed to decode request body") // Logging error
		return
	}
	if data.Destination == "" || data.EntryMethod == "" {
		http.Error(w, "Destination and EntryMethod are required", http.StatusBadRequest)
		log.Error().Msg("Destination and EntryMethod are required") // Logging error
		return
	}

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		log.Error().Msg("Invalid destination format") // Logging error
		return
	}

	// Check if the destination is unique
	existingData, err := getHostDataByDestination(data.Destination)
	if err == nil && existingData != nil {
		http.Error(w, "Destination already exists", http.StatusConflict)
		log.Error().Msg("Destination already exists") // Logging error
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
		log.Error().Err(err).Msg("Failed to insert host data") // Logging error
		return
	}
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to encode response") // Logging error
	}
	log.Info().Msg("Host data inserted successfully") // Logging success
}

func handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received update host request") // Logging request

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010" // Default port if not set
	}

	if r.Host != "localhost:"+port && r.Host != rootHost {
		handleRequest(w, r) // Pass to handleRequest
		return
	}

	var data HostData
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Error().Err(err).Msg("Failed to decode request body") // Logging error
		return
	}
	if data.Destination == "" || data.UpdaterID == "" {
		http.Error(w, "Destination and UpdaterID are required", http.StatusBadRequest)
		log.Error().Msg("Destination and UpdaterID are required") // Logging error
		return
	}

	pattern := `^bafy[a-zA-Z0-9]{50,}$`
	matched, err := regexp.MatchString(pattern, data.Destination)
	if err != nil || !matched {
		http.Error(w, "Invalid destination format", http.StatusBadRequest)
		log.Error().Msg("Invalid destination format") // Logging error
		return
	}

	existingData, err := getHostDataByHost(data.Host)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		log.Error().Err(err).Msg("Host not found") // Logging error
		return
	}

	if existingData.UpdaterID != data.UpdaterID {
		http.Error(w, "UpdaterID does not match", http.StatusForbidden)
		log.Error().Msg("UpdaterID does not match") // Logging error
		return
	}

	data.Updated = time.Now()
	err = updateHostData(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to update host data") // Logging error
		return
	}
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to encode response") // Logging error
	}
	log.Info().Msgf("Host data updated successfully for host: %s", data.Host) // Logging success with host
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqCount.WithLabelValues(r.URL.Path).Inc()
	defer func() {
		reqDuration.WithLabelValues(r.URL.Path).Observe(time.Since(start).Seconds())
	}()

	log.Info().Msg("Received health check request") // Logging request

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010" // Default port if not set
	}

	if r.Host != "localhost:"+port && r.Host != rootHost {
		handleRequest(w, r) // Pass to handleRequest
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
		http.Error(w, "Failed to write response", http.StatusInternalServerError)
		log.Error().Err(err).Msg("Failed to write response") // Logging error
	}
	log.Info().Msg("Health check response sent successfully") // Logging success
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	_ = godotenv.Load() // Ignore error if .env file is not present

	initDB()
	defer db.Close()

	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/insert", handleInsertHost)
	http.HandleFunc("/update", handleUpdateHost)
	http.HandleFunc("/health", handleHealth)    // New health endpoint
	http.Handle("/metrics", promhttp.Handler()) // Prometheus metrics endpoint

	port := os.Getenv("PORT")
	if port == "" {
		port = "3010" // Default port if not set
	}
	log.Info().Msgf("Server started on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal().Err(err).Msg("Server failed")
	}
}
