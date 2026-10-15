package harden

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRecordRoundTrip(t *testing.T) {
	root := t.TempDir()
	if r, err := LoadRecord(root); r != nil || err != nil {
		t.Fatalf("no Record yet: got %+v, %v", r, err)
	}
	ran := time.Date(2026, 10, 15, 1, 12, 0, 0, time.UTC)
	want := Record{Ran: ran, By: "root", Admin: "anh", Skipped: []string{"sysctl"},
		Applied: map[string]time.Time{"admin": ran, "fail2ban": ran}}
	if err := want.Save(root); err != nil {
		t.Fatal(err)
	}
	got, err := LoadRecord(root)
	if err != nil || !reflect.DeepEqual(*got, want) {
		t.Fatalf("got %+v, %v\nwant %+v", got, err, want)
	}
	// Written atomically: only the Record itself is left in its directory.
	if es, _ := os.ReadDir(filepath.Dir(filepath.Join(root, RecordPath))); len(es) != 1 {
		t.Errorf("directory holds %v", es)
	}
}
