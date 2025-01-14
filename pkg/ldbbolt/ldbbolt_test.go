package ldbbolt

import (
	"encoding/binary"
	"io/ioutil"
	"os"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
)

var logger = &logrus.Logger{
	Out:       os.Stderr,
	Formatter: &logrus.TextFormatter{},
	Level:     logrus.InfoLevel,
}

var baseEntry = ldap.NewEntry("o=base",
	map[string][]string{
		"o":           {"base"},
		"objectclass": {"organization"},
	})
var subEntry = ldap.NewEntry("ou=sub,o=base",
	map[string][]string{
		"ou":          {"sub"},
		"objectclass": {"organizationalUnit"},
	})
var userEntry = ldap.NewEntry("uid=user,ou=sub,o=base",
	map[string][]string{
		"uid":         {"user"},
		"displayname": {"DisplayName"},
		"mail":        {"user@example"},
		"entryuuid":   {"abcd-defg"},
	})

func setupTestDB(t *testing.T) *LdbBolt {
	bdb := &LdbBolt{}

	dbFile, err := ioutil.TempFile("", "ldbbolt_")
	if err != nil {
		t.Fatalf("Error creating tempfile: %s", err)
	}
	defer dbFile.Close()
	if err := bdb.Configure(logger, "o=base", dbFile.Name(), nil); err != nil {
		t.Fatalf("Error setting up database %s", err)
	}
	if err := bdb.Initialize(); err != nil {
		t.Fatalf("Error initializing database %s", err)
	}
	return bdb
}

func TestEntryPutSingle(t *testing.T) {
	bdb := setupTestDB(t)
	defer os.Remove(bdb.db.Path())
	defer bdb.Close()

	// adding wrong base entry fails
	if err := bdb.EntryPut(subEntry); err == nil {
		t.Fatal("Adding wrong base entry should fail")
	}

	// adding base entry succeeds
	if err := bdb.EntryPut(baseEntry); err != nil {
		t.Fatalf("Adding correct base entry should succeed. Got error:%s", err)
	}

	// adding entry without parent fails
	if err := bdb.EntryPut(userEntry); err == nil {
		t.Fatal("Adding entry without parent should fail")
	}
}

func TestEntryPutMulti(t *testing.T) {
	bdb := setupTestDB(t)
	defer os.Remove(bdb.db.Path())
	defer bdb.Close()

	// adding multiple entries succeeds
	for _, entry := range []*ldap.Entry{baseEntry, subEntry, userEntry} {
		if err := bdb.EntryPut(entry); err != nil {
			t.Fatalf("Adding more entries should succeed. Got error:%s", err)
		}
	}

	_ = bdb.db.View(func(tx *bolt.Tx) error {
		id2entry := tx.Bucket([]byte("id2entry"))
		var i int
		_ = id2entry.ForEach(func(_, _ []byte) error {
			i++
			return nil
		})
		if i != 3 {
			t.Errorf("id2enty should have exactly 3 entries now")
		}
		i = 0
		dn2id := tx.Bucket([]byte("dn2id"))
		_ = dn2id.ForEach(func(_, _ []byte) error {
			i++
			return nil
		})
		if i != 3 {
			t.Errorf("dn2id should have exactly 3 entries now")
		}

		// get id of leaf entry, this should not be present
		// as a key in the id2children bucket. See test below.
		dn, _ := ldap.ParseDN(userEntry.DN)
		leafID := dn2id.Get([]byte(NormalizeDN(dn)))

		i = 0
		id2children := tx.Bucket([]byte("id2children"))
		_ = id2children.ForEach(func(id, v []byte) error {
			i++
			if binary.LittleEndian.Uint64(id) == binary.LittleEndian.Uint64(leafID) {
				t.Errorf("id2children should not have items for leaf entries")
			} else if len(v) != 8 {
				t.Errorf("id2children each id should have exactly one 8	byte entry currently")
			}
			return nil
		})
		if i != 2 {
			t.Errorf("dn2id should have exactly 2 entries currently")
		}
		return nil
	})
}
