package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	database "github.com/blessnetwork/bless-web-ingress/db"
	"github.com/blessnetwork/bless-web-ingress/ingress"
	"github.com/docker/go-connections/nat"
	_ "github.com/mattn/go-sqlite3"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
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

func TestAPI_Execute(t *testing.T) {

	var (
		ctx = context.Background()
	)

	shutdown := startNodes(t, ctx)
	defer shutdown(ctx)

}

func startNodes(t *testing.T, ctx context.Context) (shutdownFunc func(context.Context) error) {
	t.Helper()

	var (
		b7sImage      = "ghcr.io/blessnetwork/b7s:v0.7.5"
		headP2PPort   = "9000"
		headAPIPort   = "8888"
		workerP2PPort = "9100"
		keyPath       = "/app/key.bin"

		shutdown []func(context.Context) error
	)

	defer func() {
		shutdownFunc = shutdownAll(shutdown)
	}()

	net, err := network.New(ctx)
	require.NoError(t, err)

	shutdown = append(shutdown, net.Remove)

	head, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: b7sImage,
				Name:  "b7s-head",
				ExposedPorts: []string{
					headP2PPort + "/tcp",
					fmt.Sprintf("%v/tcp:%v/tcp", headAPIPort, headAPIPort),
				},
				Networks: []string{net.Name},
				WaitingFor: wait.ForHTTP("/api/v1/health").
					WithPort(nat.Port(headAPIPort + "/tcp")).
					WithStartupTimeout(10 * time.Second),
				Env: map[string]string{
					"NODE_ROLE":     "head",
					"REST_API":      headAPIPort,
					"P2P_PORT":      headP2PPort,
					"NODE_KEY_PATH": keyPath,
				},
				Files: []testcontainers.ContainerFile{
					{
						HostFilePath:      "testdata/keys/head/priv.bin",
						ContainerFilePath: keyPath,
						FileMode:          0o640,
					},
				},
			},
			Started: true,
		},
	)
	require.NoError(t, err)

	err = head.Start(ctx)
	require.NoError(t, err)

	defer head.Stop(ctx, nil)

	shutdown = append(shutdown, func(ctx context.Context) error { return head.Stop(ctx, nil) })

	headIP, err := head.ContainerIP(ctx)
	require.NoError(t, err)

	headNodeID, err := os.ReadFile("testdata/keys/head/peerid.txt")
	require.NoError(t, err)

	worker, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image: b7sImage,
				Name:  "b7s-worker",
				ExposedPorts: []string{
					workerP2PPort + "/tcp",
				},
				Networks: []string{net.Name},
				Env: map[string]string{
					"NODE_ROLE":     "worker",
					"P2P_PORT":      workerP2PPort,
					"NODE_KEY_PATH": keyPath,
					"BOOT_NODES":    fmt.Sprintf("/ip4/%v/tcp/%v/p2p/%v", headIP, headP2PPort, string(headNodeID)),
				},
				Files: []testcontainers.ContainerFile{
					{
						HostFilePath:      "testdata/keys/worker/priv.bin",
						ContainerFilePath: keyPath,
						FileMode:          0o640,
					},
				},
			},
		},
	)
	require.NoError(t, err)

	err = worker.Start(ctx)
	require.NoError(t, err)

	shutdown = append(shutdown, func(ctx context.Context) error { return worker.Stop(ctx, nil) })

	// Deferred call will take care of setting up the shutdown function.
	return nil
}

func shutdownAll(fns []func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		var errs []error

		for _, fn := range fns {
			err := fn(ctx)
			if err != nil {
				errs = append(errs, err)
			}
		}

		return errors.Join(errs...)
	}
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
