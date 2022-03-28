package oracle

// it is expected to have running https://dev.to/zankyr/create-an-oracle-database-docker-image-1e2n

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/k1LoW/tbls/schema"
	_ "github.com/sijms/go-ora"
	"github.com/xo/dburl"
)

var s *schema.Schema
var db *sql.DB

func TestMain(m *testing.M) {
	s = &schema.Schema{
		Name: "HR",
	}
	var err error
	db, err = dburl.Open(`oracle://SYS:aB3456789@localhost:51521/XEPDB1?DBA PRIVILEGE=SYSDBA`)
	if err != nil {
		fmt.Println(err)
	}
	defer db.Close()
	exit := m.Run()
	if exit != 0 {
		os.Exit(exit)
	}
}

func TestAnalyzeView(t *testing.T) {
	driver := New(db)
	err := driver.Analyze(s)
	if err != nil {
		t.Errorf("%v", err)
	}
	view, _ := s.FindTableByName("HR.COUNTRIES")
	want := view.Name
	if want == "" {
		t.Errorf("got not empty string.")
	}
}

func TestInfo(t *testing.T) {
	driver := New(db)
	d, err := driver.Info()
	if err != nil {
		t.Errorf("%v", err)
	}
	if d.Name != "oracle" {
		t.Errorf("got %v\nwant %v", d.Name, "oracle")
	}
	if d.DatabaseVersion == "" {
		t.Errorf("got not empty string.")
	}
}
