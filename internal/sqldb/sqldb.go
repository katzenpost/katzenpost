// sqldb.go - Katzenpost server SQL database integration.
// Copyright (C) 2018  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package sqldb interfaces the Katzenpost server with a SQL database.
package sqldb

import (
	"fmt"

	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/spool"
	"github.com/katzenpost/server/userdb"
	"gopkg.in/op/go-logging.v1"
)

type dbImpl interface {
	IsSpoolOnly() bool
	UserDB() (userdb.UserDB, error)
	Spool() spool.Spool
	Close()
}

// SQLDB is a SQL database instance.
type SQLDB struct {
	glue glue.Glue
	log  *logging.Logger

	impl dbImpl
}

// IsSpoolOnly returns true iff the database is configured to only support
// acting as a user message spool.
func (d *SQLDB) IsSpoolOnly() bool {
	return d.impl.IsSpoolOnly()
}

// UserDB returns a userdb.UserDB instance backed by the SQL database.
func (d *SQLDB) UserDB() (userdb.UserDB, error) {
	return d.impl.UserDB()
}

// Spool returns a spool.Spool instance backed by the SQL database.
func (d *SQLDB) Spool() spool.Spool {
	return d.impl.Spool()
}

// Close closes the SQL database connection(s).
func (d *SQLDB) Close() {
	d.impl.Close()
}

// New constructs a new SQLDB instance.
func New(glue glue.Glue) (*SQLDB, error) {
	db := &SQLDB{
		glue: glue,
		log:  glue.LogBackend().GetLogger("sqldb"),
	}

	sCfg := glue.Config().Provider.SQLDB

	switch sCfg.Backend {
	case implPgx:
		var err error
		db.impl, err = newPgxImpl(db, sCfg.DataSourceName)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("sqldb: Invalid backend: '%v'", sCfg.Backend)
	}

	return db, nil
}
