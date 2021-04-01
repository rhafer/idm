/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package handler

import (
	"stash.kopano.io/kgol/kidm/internal/ldapserver"
)

// Interface for handlers.
type Handler interface {
	ldapserver.Binder
	ldapserver.Searcher
	ldapserver.Closer
}

// Interface for middlewares.
type Middleware interface {
	WithHandler(next Handler) Handler
}