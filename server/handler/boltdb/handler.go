/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package boltdb

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"

	"github.com/libregraph/idm/pkg/ldappassword"
	"github.com/libregraph/idm/pkg/ldapserver"
	"github.com/libregraph/idm/pkg/ldbbolt"
	"github.com/libregraph/idm/server/handler"
)

type boltdbHandler struct {
	logger                  logrus.FieldLogger
	dbfile                  string
	baseDN                  string
	allowLocalAnonymousBind bool
	ctx                     context.Context
	bdb                     *ldbbolt.LdbBolt
}

type Options struct {
	BaseDN                  string
	AllowLocalAnonymousBind bool
}

func NewBoltDBHandler(logger logrus.FieldLogger, fn string, options *Options) (handler.Handler, error) {
	if fn == "" {
		return nil, fmt.Errorf("file name is empty")
	}
	if options.BaseDN == "" {
		return nil, fmt.Errorf("base dn is empty")
	}

	fn, err := filepath.Abs(fn)
	if err != nil {
		return nil, err
	}
	logger = logger.WithField("db", fn)

	h := &boltdbHandler{
		logger: logger,
		dbfile: fn,

		baseDN:                  strings.ToLower(options.BaseDN),
		allowLocalAnonymousBind: options.AllowLocalAnonymousBind,
		ctx:                     context.Background(),
	}

	err = h.setup()
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *boltdbHandler) setup() error {
	bdb := &ldbbolt.LdbBolt{}

	if err := bdb.Configure(h.logger, h.baseDN, h.dbfile, nil); err != nil {
		return err
	}

	if err := bdb.Initialize(); err != nil {
		return err
	}
	h.bdb = bdb
	return nil
}

func (h *boltdbHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldapserver.LDAPResultCode, error) {
	logger := h.logger.WithFields(logrus.Fields{
		"op":          "bind",
		"bind_dn":     bindDN,
		"remote_addr": conn.RemoteAddr().String(),
	})

	// Handle anoymous bind
	if bindDN == "" {
		if !h.allowLocalAnonymousBind {
			logger.Debugln("ldap anonymous Bind disabled")
			return ldap.LDAPResultInvalidCredentials, nil
		} else if bindSimplePw == "" {
			return ldap.LDAPResultSuccess, nil
		}
	}

	dn, err := ldap.ParseDN(bindDN)
	if err != nil {
		logger.WithError(err).Debugln("ldap bind request BindDN validation failed")
		return ldap.LDAPResultInvalidDNSyntax, nil
	}
	bindDN = ldbbolt.NormalizeDN(dn)

	if !strings.HasSuffix(bindDN, h.baseDN) {
		logger.WithError(err).Debugln("ldap bind request BindDN outside of Database tree")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	// Disallow empty password
	if bindSimplePw == "" {
		logger.Debugf("BindDN without password")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	return h.validatePassword(logger, bindDN, bindSimplePw)
}

func (h *boltdbHandler) validatePassword(logger logrus.FieldLogger, bindDN, bindSimplePw string) (ldapserver.LDAPResultCode, error) {
	// Lookup Bind DN in database
	entries, err := h.bdb.Search(bindDN, ldap.ScopeBaseObject)
	if err != nil || len(entries) != 1 {
		if err != nil {
			logger.Error(err)
		}
		if len(entries) != 1 {
			logger.Debugf("Entry '%s' does not exist", bindDN)
		}
		return ldap.LDAPResultInvalidCredentials, nil
	}
	userPassword := entries[0].GetAttributeValue("userPassword")
	match, err := ldappassword.Validate(bindSimplePw, userPassword)
	if err != nil {
		logger.Error(err)
		return ldap.LDAPResultInvalidCredentials, nil
	}
	if match {
		logger.Debug("success")
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

func (h *boltdbHandler) Search(boundDN string, req *ldap.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
	h.logger.WithField("op", "search").Debug("start")

	entries, _ := h.bdb.Search(req.BaseDN, req.Scope)

	return ldapserver.ServerSearchResult{
		Entries:    entries,
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

func (h *boltdbHandler) Close(boundDN string, conn net.Conn) error {
	return nil
}

func (h *boltdbHandler) WithContext(ctx context.Context) handler.Handler {
	if ctx == nil {
		panic("nil context")
	}

	h2 := new(boltdbHandler)
	*h2 = *h
	h2.ctx = ctx
	return h2
}

func (h *boltdbHandler) Reload(ctx context.Context) error {
	return nil
}
