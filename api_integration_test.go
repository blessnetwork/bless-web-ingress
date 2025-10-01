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

	var (
		addr           = "127.0.0.1:" + DefaultAppPort
		insertEndpoint = fmt.Sprintf("http://%s/insert", addr)
		updateEndpoint = fmt.Sprintf("http://%s/update", addr)

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
		sampleRec = ingress.Host{
			Destination: "bafybeie3nlygbnuxhvqv3gvwa2hmd4tcfzk5jtvscwl6qs3ljn5tknlt4q",
			EntryMethod: "echo.wasm",
			ReturnType:  ReturnTypeRaw,
			Permissions: []string{"a", "b", "c"},
		}

		// Fields known after insert
		updaterID string
		hostID    string
	)

	t.Run("insert", func(t *testing.T) {

		start := time.Now()

		res, err := http.Post(insertEndpoint, "application/json", bytes.NewReader(serialize(t, sampleRec)))
		require.NoError(t, err)
		defer res.Body.Close()

		require.Equal(t, http.StatusCreated, res.StatusCode)

		var returned ingress.Host
		err = json.NewDecoder(res.Body).Decode(&returned)
		require.NoError(t, err)

		require.Equal(t, sampleRec.Destination, returned.Destination)
		require.Equal(t, sampleRec.EntryMethod, returned.EntryMethod)
		require.Equal(t, sampleRec.NumberOfNodes, returned.NumberOfNodes)
		require.Equal(t, sampleRec.Permissions, returned.Permissions)
		require.Equal(t, sampleRec.ReturnType, returned.ReturnType)

		require.NotZero(t, returned.Host)
		require.NotZero(t, returned.UpdaterID)

		require.True(t, returned.Created.After(start))
		require.True(t, returned.Updated.After(start))

		// Record this as we'll need it for updating.
		updaterID = returned.UpdaterID
		hostID = returned.Host
	})
	t.Run("update", func(t *testing.T) {

		start := time.Now()

		updated := sampleRec
		updated.EntryMethod = "updated-entry.wasm"
		updated.Host = hostID
		updated.UpdaterID = updaterID

		res, err := http.Post(updateEndpoint, "application/json", bytes.NewReader(serialize(t, updated)))
		require.NoError(t, err)

		defer res.Body.Close()

		require.Equal(t, http.StatusOK, res.StatusCode)

		var returned ingress.Host
		err = json.NewDecoder(res.Body).Decode(&returned)
		require.NoError(t, err)

		require.Equal(t, updated.Destination, returned.Destination)
		require.Equal(t, updated.EntryMethod, returned.EntryMethod)
		require.Equal(t, updated.Permissions, returned.Permissions)
		require.Equal(t, updated.ReturnType, returned.ReturnType)

		require.NotZero(t, returned.Host)
		require.NotZero(t, returned.UpdaterID)

		require.True(t, returned.Updated.After(start))
	})
	t.Run("update with wrong updater ID fails", func(t *testing.T) {

		updated := sampleRec
		updated.EntryMethod = "updated-entry.wasm"
		updated.Host = hostID
		updated.UpdaterID = updaterID + "1"

		res, err := http.Post(updateEndpoint, "application/json", bytes.NewReader(serialize(t, updated)))
		require.NoError(t, err)

		defer res.Body.Close()

		require.Equal(t, http.StatusForbidden, res.StatusCode)
	})
	t.Run("insert of identical destination fails", func(t *testing.T) {

		rec := ingress.Host{
			Destination: sampleRec.Destination,
			EntryMethod: "whatever.wasm",
			Permissions: []string{"a"},
		}

		res, err := http.Post(insertEndpoint, "application/json", bytes.NewReader(serialize(t, rec)))
		require.NoError(t, err)
		defer res.Body.Close()

		require.Equal(t, http.StatusConflict, res.StatusCode)

	})
	t.Run("insert of invalid destination fails", func(t *testing.T) {

		rec := ingress.Host{
			Destination: "random-malformed-cid",
			EntryMethod: "whatever.wasm",
			Permissions: []string{"a"},
		}

		res, err := http.Post(insertEndpoint, "application/json", bytes.NewReader(serialize(t, rec)))
		require.NoError(t, err)
		defer res.Body.Close()

		require.Equal(t, http.StatusBadRequest, res.StatusCode)
	})
}

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
