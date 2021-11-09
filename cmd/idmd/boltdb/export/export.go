/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package export

import (
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/libregraph/idm/pkg/ldbbolt"
)

type LDIFExporter struct {
	logger logrus.FieldLogger
	dbFile string
	baseDN string
}

func NewLDIFExporter(logLevel, dbFile, base string) (*LDIFExporter, error) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}

	res := &LDIFExporter{
		logger: &logrus.Logger{
			Out:       os.Stderr,
			Formatter: &logrus.TextFormatter{},
			Level:     level,
		},
		dbFile: dbFile,
		baseDN: base,
	}
	return res, nil
}

func (l *LDIFExporter) Export() error {
	bdb := &ldbbolt.LdbBolt{}

	bdb.Configure(l.logger, l.baseDN, l.dbFile, &bolt.Options{ReadOnly: true})

	if err := bdb.Initialize(); err != nil {
		return err
	}
	defer bdb.Close()

	entries, err := bdb.Search(l.baseDN, ldap.ScopeWholeSubtree)
	if err != nil {
		l.logger.Error(err)
	}

	ld, err := ldif.ToLDIF(entries)
	if err != nil {
		l.logger.Error(err)
	}

	output, err := ldif.Marshal(ld)
	if err != nil {
		l.logger.Error(err)
	}

	fmt.Printf(output)
	return nil
}
