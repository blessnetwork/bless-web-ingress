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

	var (
		rec = ingress.Host{
			Destination:   "bafybeie3nlygbnuxhvqv3gvwa2hmd4tcfzk5jtvscwl6qs3ljn5tknlt4q",
			EntryMethod:   "echo.wasm",
			NumberOfNodes: 1,
			ReturnType:    ReturnTypeRaw,
			Permissions:   []string{"a", "b", "c"},
		}

		// Fields known after insert
		updaterID string
		hostID    string
	)

	t.Run("insert", func(t *testing.T) {

		var (
			addr  = fmt.Sprintf("http://%s/insert", addr)
			start = time.Now()
		)

		res, err := http.Post(addr, "application/json", bytes.NewReader(serialize(t, rec)))
		require.NoError(t, err)
		defer res.Body.Close()

		require.Equal(t, http.StatusCreated, res.StatusCode)

		var returned ingress.Host
		err = json.NewDecoder(res.Body).Decode(&returned)
		require.NoError(t, err)

		require.Equal(t, rec.Destination, returned.Destination)
		require.Equal(t, rec.EntryMethod, returned.EntryMethod)
		require.Equal(t, rec.NumberOfNodes, returned.NumberOfNodes)
		require.Equal(t, rec.Permissions, returned.Permissions)
		require.Equal(t, rec.ReturnType, returned.ReturnType)

		require.NotZero(t, returned.Host)
		require.NotZero(t, returned.UpdaterID)

		require.NotZero(t, returned.Created)
		require.NotZero(t, returned.Updated)

		require.True(t, returned.Created.After(start))
		require.True(t, returned.Updated.After(start))

		// Record this as we'll need it for updating.
		updaterID = returned.UpdaterID
		hostID = returned.Host
	})
	t.Run("update", func(t *testing.T) {

		var (
			addr  = fmt.Sprintf("http://%s/update", addr)
			start = time.Now()
		)

		// TODO: Updater ID.

		updated := rec
		updated.EntryMethod = "updated-entry.wasm"
		updated.NumberOfNodes = 2
		updated.Host = hostID
		updated.UpdaterID = updaterID // + "1"

		res, err := http.Post(addr, "application/json", bytes.NewReader(serialize(t, updated)))
		require.NoError(t, err)

		defer res.Body.Close()

		require.Equal(t, http.StatusOK, res.StatusCode)

		var returned ingress.Host
		err = json.NewDecoder(res.Body).Decode(&returned)
		require.NoError(t, err)

		require.Equal(t, updated.Destination, returned.Destination)
		require.Equal(t, updated.EntryMethod, returned.EntryMethod)
		require.Equal(t, updated.NumberOfNodes, returned.NumberOfNodes)
		require.Equal(t, updated.Permissions, returned.Permissions)
		require.Equal(t, updated.ReturnType, returned.ReturnType)

		require.NotZero(t, returned.Host)
		require.NotZero(t, returned.UpdaterID)

		require.NotZero(t, returned.Updated)
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
