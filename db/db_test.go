package db

import (
	"database/sql"
	"fmt"
	"math/rand/v2"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/blessnetwork/bless-web-ingress/ingress"
	"github.com/stretchr/testify/require"
)

func TestDB_Host(t *testing.T) {

	var (
		orig = ingress.Host{
			Destination:       fmt.Sprintf("destination-%d", rand.Int()),
			EntryMethod:       fmt.Sprintf("echo-%d.wasm", rand.Int()),
			ReturnType:        fmt.Sprintf("return-type-%d", rand.Int()),
			UpdaterID:         fmt.Sprintf("updater-id-%d", rand.Int()),
			PermissionsString: fmt.Sprintf("rand-permissions-%d", rand.Int()),
		}
		db, shutdown = createDB(t)
	)
	defer shutdown(t)

	t.Run("insert host", func(t *testing.T) {
		err := db.InsertHostData(orig)
		require.NoError(t, err)
	})
	t.Run("retrieve host", func(t *testing.T) {

		read, err := db.GetHostDataByHost(orig.Host)
		require.NoError(t, err)

		require.Equal(t, orig, *read)
	})
	t.Run("retrieve destination", func(t *testing.T) {

		read, err := db.GetHostDataByDestination(orig.Destination)
		require.NoError(t, err)

		require.Equal(t, orig, *read)
	})
	t.Run("update host", func(t *testing.T) {

		updated := orig
		updated.Destination += "1"
		updated.UpdaterID += "1"

		err := db.UpdateHostData(updated)
		require.NoError(t, err)

		read, err := db.GetHostDataByHost(updated.Host)
		require.NoError(t, err)

		require.Equal(t, updated, *read)

		read, err = db.GetHostDataByDestination(updated.Destination)
		require.NoError(t, err)
		require.Equal(t, updated, *read)
	})
}

func createDB(t *testing.T) (*DB, func(t *testing.T)) {
	t.Helper()

	f, err := os.CreateTemp("", "ingress-db-")
	require.NoError(t, err)

	rawDB, err := sql.Open("sqlite3", f.Name())
	require.NoError(t, err)

	db, err := NewDB(rawDB, true)
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
