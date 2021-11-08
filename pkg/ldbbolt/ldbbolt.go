/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

// Package ldbbolt provides the lower-level Database functions for managing LDAP Entries
// in a	BoltDB database. Some implementation details:
//
// The database is currently separated in these three buckets
//
// - id2entry: This bucket contains the GOB encoded ldap.Entry instances keyed
//             by a unique 64bit ID
//
// - dn2id: This bucket is used as an index to lookup the ID of an entry by its DN. The DN
//          is used in an normalized (case-folded) form here.
//
// - id2children: This bucket uses the entry-ids as and index and the values contain a list
//                of the entry ids of its direct childdren
//
// Additional buckets will likely be added in the future to create efficient search indexes
package ldbbolt

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/cases"
)

type LdbBolt struct {
	logger logrus.FieldLogger
	db     *bolt.DB
	base   string
}

func (bdb *LdbBolt) Configure(logger logrus.FieldLogger, baseDN string, dbfile string) error {
	bdb.logger = logger
	logger.Debugf("Open boltdb %s", dbfile)
	db, err := bolt.Open(dbfile, 0600, nil)
	if err != nil {
		bdb.logger.WithError(err).Error("Error opening database")
		return err
	}
	bdb.db = db
	dn, _ := ldap.ParseDN(baseDN)
	bdb.base = NormalizeDN(dn)
	return nil
}

// Initialize() opens the Database file and create the required buckets if they do not
// exist yet. After calling initialize the database is ready to process transactions
func (bdb *LdbBolt) Initialize() error {
	bdb.logger.Debug("Adding default buckets")
	err := bdb.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("dn2id"))
		if err != nil {
			return fmt.Errorf("create bucket 'dn2id': %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("id2children"))
		if err != nil {
			return fmt.Errorf("create bucket 'dn2id': %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte("id2entry"))
		if err != nil {
			return fmt.Errorf("create bucket 'id2entry': %w", err)
		}
		return nil
	})
	if err != nil {
		bdb.logger.WithError(err).Error("Error creating default buckets")
	}
	return err
}

// While formally some RDN attributes could be casesensitive
// maybe we should just skip the DN parsing and just casefold
// the entire DN string?
func NormalizeDN(dn *ldap.DN) string {
	var nDN string
	caseFold := cases.Fold()
	for r, rdn := range dn.RDNs {
		// FIXME to really normalize multivalued RDNs we'd need
		// to normalize the order of Attributes here as well
		for a, ava := range rdn.Attributes {
			if a > 0 {
				// This is a multivalued RDN.
				nDN += "+"
			} else if r > 0 {
				nDN += ","
			}
			nDN = nDN + caseFold.String(ava.Type) + "=" + caseFold.String(ava.Value)
		}
	}
	return nDN
}

// Performs basic LDAP searchs, using the dn2id and id2children buckets to generate
// a list of Result entries. Currently this does strip of the non-request attribute
// Neither does it support LDAP filters. For now we rely on the frontent (LDAPServer)
// to both.
func (bdb *LdbBolt) Search(base string, scope int) ([]*ldap.Entry, error) {
	entries := []*ldap.Entry{}
	dn, _ := ldap.ParseDN(base)
	nDN := NormalizeDN(dn)

	err := bdb.db.View(func(tx *bolt.Tx) error {
		entryID := bdb.GetIdByDN(tx, nDN)
		var entryIDs []uint64
		if entryID == 0 {
			return fmt.Errorf("not found")
		}
		switch scope {
		case ldap.ScopeBaseObject:
			entryIDs = append(entryIDs, entryID)
		case ldap.ScopeSingleLevel:
			entryIDs = bdb.GetChildrenIDs(tx, entryID)
		case ldap.ScopeWholeSubtree:
			entryIDs = append(entryIDs, entryID)
			entryIDs = append(entryIDs, bdb.GetSubtreeIDs(tx, entryID)...)
		}
		id2entry := tx.Bucket([]byte("id2entry"))
		for _, id := range entryIDs {
			entrybytes := id2entry.Get(idToBytes(id))
			buf := bytes.NewBuffer(entrybytes)
			dec := gob.NewDecoder(buf)
			var entry ldap.Entry
			dec.Decode(&entry)
			entries = append(entries, &entry)
		}
		return nil
	})
	return entries, err
}

func idToBytes(id uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, id)
	return b
}

func (bdb *LdbBolt) GetChildrenIDs(tx *bolt.Tx, parent uint64) []uint64 {
	bdb.logger.Debugf("GetChildrenIDs '%d'", parent)
	id2Children := tx.Bucket([]byte("id2children"))
	children := id2Children.Get(idToBytes(parent))
	r := bytes.NewReader(children)
	ids := make([]uint64, len(children)/8)
	if err := binary.Read(r, binary.LittleEndian, &ids); err != nil {
		bdb.logger.Error(err)
	}
	bdb.logger.Debugf("Children '%v'\n", ids)
	return ids
}

func (bdb *LdbBolt) GetSubtreeIDs(tx *bolt.Tx, root uint64) []uint64 {
	bdb.logger.Debugf("GetSubtreeIDs '%d'", root)
	var res []uint64
	children := bdb.GetChildrenIDs(tx, root)
	res = append(res, children...)
	for _, child := range children {
		res = append(res, bdb.GetSubtreeIDs(tx, child)...)
	}
	bdb.logger.Debugf("GetSubtreeIDs '%v'", res)
	return res
}

func (bdb *LdbBolt) EntryPut(e *ldap.Entry) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(e); err != nil {
		fmt.Printf("%v\n", err)
		panic(err)
	}

	dn, _ := ldap.ParseDN(e.DN)
	parentDN := &ldap.DN{
		RDNs: dn.RDNs[1:],
	}
	nDN := NormalizeDN(dn)

	if !strings.HasSuffix(nDN, bdb.base) {
		return fmt.Errorf("'%s' is not a descendant of '%s'", e.DN, bdb.base)
	}

	nParentDN := NormalizeDN(parentDN)
	err := bdb.db.Update(func(tx *bolt.Tx) error {
		id2entry := tx.Bucket([]byte("id2entry"))
		id := bdb.GetIdByDN(tx, nDN)
		if id == 0 {
			var err error
			if id, err = id2entry.NextSequence(); err != nil {
				return err
			}
		}

		if err := id2entry.Put(idToBytes(id), buf.Bytes()); err != nil {
			return err
		}
		if nDN != bdb.base {
			if err := bdb.AddId2Children(tx, nParentDN, id); err != nil {
				return err
			}
		}
		dn2id := tx.Bucket([]byte("dn2id"))
		if err := dn2id.Put([]byte(nDN), idToBytes(id)); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (bdb *LdbBolt) AddId2Children(tx *bolt.Tx, nParentDN string, newChildID uint64) error {
	bdb.logger.Debugf("AddId2Children '%s' id '%d'", nParentDN, newChildID)
	parentId := bdb.GetIdByDN(tx, nParentDN)
	if parentId == 0 {
		return fmt.Errorf("parent not found '%s'", nParentDN)
	}

	bdb.logger.Debugf("Parent ID: %v", parentId)

	id2Children := tx.Bucket([]byte("id2children"))

	// FIXME add sanity check here if ID is already present
	children := id2Children.Get(idToBytes(parentId))
	children = append(children, idToBytes(newChildID)...)
	id2Children.Put(idToBytes(parentId), children)
	bdb.logger.Debugf("AddId2Children '%d' id '%v'", parentId, children)
	return nil
}

func (bdb *LdbBolt) GetIdByDN(tx *bolt.Tx, nDN string) uint64 {
	dn2id := tx.Bucket([]byte("dn2id"))
	id := dn2id.Get([]byte(nDN))
	if id == nil {
		bdb.logger.Debugf("DN: '%s' not found", nDN)
		return 0
	}
	return binary.LittleEndian.Uint64(id)
}

func (bdb *LdbBolt) Close() {
	bdb.db.Close()
}
