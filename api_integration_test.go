package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	database "github.com/blessnetwork/bless-web-ingress/db"
	"github.com/blessnetwork/bless-web-ingress/ingress"
	_ "github.com/mattn/go-sqlite3"

	"github.com/stretchr/testify/require"
)

func TestAPI(t *testing.T) {

	const (
		addr = "127.0.0.1:" + DefaultAppPort
	)

	var (
		db, shutdown = createDB(t)
		api          = newAPI(addr, db)
	)
	defer shutdown(t)

	go func() {
		err := api.Start()
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()
	defer func() {
		err := api.Shutdown(context.Background())
		require.NoError(t, err)
	}()

	// Slight delay to allow for the server to start.
	time.Sleep(200 * time.Millisecond)

	t.Run("insert", func(t *testing.T) {

		var (
			addr = fmt.Sprintf("http://%s/insert", addr)

			req = ingress.Host{
				Destination:   "bafybeie3nlygbnuxhvqv3gvwa2hmd4tcfzk5jtvscwl6qs3ljn5tknlt4q",
				EntryMethod:   "echo.wasm",
				NumberOfNodes: 1,
				ReturnType:    ReturnTypeRaw,
				Permissions:   []string{"a", "b", "c"},
			}

			payload = serialize(t, req)

			start = time.Now()
		)

		res, err := http.Post(addr, "application/json", bytes.NewReader(payload))
		require.NoError(t, err)

		require.Equal(t, res.StatusCode, http.StatusCreated)
		defer res.Body.Close()

		var returned ingress.Host
		err = json.NewDecoder(res.Body).Decode(&returned)
		require.NoError(t, err)

		require.Equal(t, req.Destination, returned.Destination)
		require.Equal(t, req.EntryMethod, returned.EntryMethod)
		require.Equal(t, req.NumberOfNodes, returned.NumberOfNodes)
		require.Equal(t, req.Permissions, returned.Permissions)
		require.Equal(t, req.ReturnType, returned.ReturnType)

		require.NotZero(t, returned.Host)
		require.NotZero(t, returned.UpdaterID)

		require.NotZero(t, returned.Created)
		require.NotZero(t, returned.Updated)

		require.True(t, returned.Created.After(start))
		require.True(t, returned.Updated.After(start))
	})
}

// TODO: Just return a shutdown function and keep everything else hidden.
func createDB(t *testing.T) (*database.DB, func(t *testing.T)) {
	t.Helper()

	f, err := os.CreateTemp("", "ingress-db-")
	require.NoError(t, err)

	rawDB, err := sql.Open("sqlite3", f.Name())
	require.NoError(t, err)

	db, err := database.NewDB(rawDB, true)
	require.NoError(t, err)

	shutdown := func(t *testing.T) {
		t.Helper()

		err := db.Close()
		require.NoError(t, err)

		name := f.Name()

		err = f.Close()
		require.NoError(t, err)

		err = os.Remove(name)
		require.NoError(t, err)
	}

	return db, shutdown
}

func serialize(t *testing.T, obj any) []byte {
	t.Helper()

	data, err := json.Marshal(obj)
	require.NoError(t, err)

	return data
}
