package file

import (
	"errors"
	"slices"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
)

var errSync = errors.New("sync failed")

// fakeFile records the order of writes and syncs, and fails a sync on demand, which a real file cannot do.
type fakeFile struct {
	calls   []string
	syncErr error
}

func (f *fakeFile) Write(p []byte) (int, error) {
	f.calls = append(f.calls, "write")
	return len(p), nil
}

func (f *fakeFile) Sync() error {
	f.calls = append(f.calls, "sync")
	return f.syncErr
}

func (f *fakeFile) Close() error {
	return nil
}

func TestWriteSync(t *testing.T) {
	t.Run("a sink set to sync syncs after each record", func(t *testing.T) {
		f := &fakeFile{}
		sink := newSink(f, true)

		for range 2 {
			if err := sink.Write(t.Context(), audit.Event{}); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}

		if want := []string{"write", "sync", "write", "sync"}; !slices.Equal(f.calls, want) {
			t.Errorf("got %v, want %v", f.calls, want)
		}
	})

	t.Run("a sink not set to sync does not sync", func(t *testing.T) {
		f := &fakeFile{}
		sink := newSink(f, false)

		if err := sink.Write(t.Context(), audit.Event{}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		if want := []string{"write"}; !slices.Equal(f.calls, want) {
			t.Errorf("got %v, want %v", f.calls, want)
		}
	})

	t.Run("a failed sync fails the write", func(t *testing.T) {
		sink := newSink(&fakeFile{syncErr: errSync}, true)

		err := sink.Write(t.Context(), audit.Event{})

		if !errors.Is(err, errSync) {
			t.Errorf("got %v, want %v", err, errSync)
		}
	})
}
