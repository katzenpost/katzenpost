// pgx.go - Postgresql database support.
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

package sqldb

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/spool"
	"github.com/katzenpost/katzenpost/server/userdb"
)

const (
	implPgx = "pgx"

	pgxTagUserDelete      = "user_delete"
	pgxTagUserGetAuthKey  = "user_get_authentication_key"
	pgxTagUserSetAuthKey  = "user_set_authentication_key"
	pgxTagUserGetIdentKey = "user_get_identity_key"
	pgxTagUserSetIdentKey = "user_set_identity_key"
	pgxTagSpoolStore      = "spool_store"
	pgxTagSpoolGet        = "spool_get"

	pgCodeNoDataFound = "P0002" // `no_data_found`
)

type pgxImpl struct {
	d *SQLDB

	pool *pgx.ConnPool

	spoolOnly bool
}

func (p *pgxImpl) IsSpoolOnly() bool {
	return p.spoolOnly
}

func (p *pgxImpl) UserDB() (userdb.UserDB, error) {
	if p.IsSpoolOnly() {
		return nil, errors.New("sql/pgx: UserDB() called for spool only database")
	}
	return newPgxUserDB(p), nil
}

func (p *pgxImpl) Spool() spool.Spool {
	return newPgxSpool(p)
}

func (p *pgxImpl) Close() {
	p.pool.Close()
}

func (p *pgxImpl) Log(level pgx.LogLevel, msg string, data map[string]interface{}) {
	if level == pgx.LogLevelNone {
		return
	}

	argVec := make([]interface{}, 0, 1+len(data))
	argVec = append(argVec, msg+" ")
	for k, v := range data {
		argVec = append(argVec, fmt.Sprintf("%s=%v ", k, v))
	}
	mStr := strings.TrimSpace(fmt.Sprint(argVec...))

	switch level {
	case pgx.LogLevelDebug:
		p.d.log.Debug(mStr)
	case pgx.LogLevelInfo:
		p.d.log.Info(mStr)
	case pgx.LogLevelWarn:
		p.d.log.Warning(mStr)
	case pgx.LogLevelError:
		p.d.log.Error(mStr)
	}
}

func (p *pgxImpl) initMetadata() error {
	const (
		metadataQuery    = "SELECT * FROM metadata_get() AS (schema_version smallint, spool_only boolean);"
		pgxSchemaVersion = 0
	)

	var schemaVersion int
	err := p.pool.QueryRow(metadataQuery).Scan(&schemaVersion, &p.spoolOnly)
	switch {
	case err == pgx.ErrNoRows:
		return fmt.Errorf("sql/pgx: database missing metadata table?")
	case err != nil:
		return fmt.Errorf("sql/pgx: metadata_get() failed: %v", err)
	default:
		if schemaVersion != pgxSchemaVersion {
			return fmt.Errorf("sql/pgx: invalid schema version: %v", schemaVersion)
		}
	}

	return nil
}

func (p *pgxImpl) initStatements() error {
	stmts := []struct {
		tag, query string
	}{
		{pgxTagUserDelete, "SELECT user_delete($1);"},
		{pgxTagUserGetAuthKey, "SELECT user_get_authentication_key($1);"},
		{pgxTagUserSetAuthKey, "SELECT user_set_authentication_key($1, $2, $3);"},
		{pgxTagUserGetIdentKey, "SELECT user_get_identity_key($1);"},
		{pgxTagUserSetIdentKey, "SELECT user_set_identity_key($1, $2);"},
		{pgxTagSpoolStore, "SELECT spool_store($1, $2, $3);"},
		{pgxTagSpoolGet, "SELECT * FROM spool_get($1, $2) AS (message_body bytea, surb_id bytea, remaining integer);"},
	}

	for _, v := range stmts {
		if _, err := p.pool.Prepare(v.tag, v.query); err != nil {
			p.d.log.Errorf("Failed to prepare statement %v -> %v: %v", v.tag, v.query, err)
			return err
		}
	}

	return nil
}

func (p *pgxImpl) doUserDelete(u []byte) error {
	_, err := p.pool.Exec(pgxTagUserDelete, u)
	return err
}

func newPgxImpl(db *SQLDB, dataSourceName string) (dbImpl, error) {
	// The pgx connection pool code requires at least 2 conns, and internally
	// will default to 5 if unspecified.  At a minimum all of the provider
	// workers should be able to hit up the database simultaneously, while
	// allowing for sufficient connections to authenticate.
	numConns := 2 * db.glue.Config().Debug.NumProviderWorkers
	if numConns < 5 {
		numConns = 5
	}

	p := &pgxImpl{
		d: db,
	}

	connCfg, err := pgx.ParseConnectionString(dataSourceName)
	if err != nil {
		return nil, err
	}
	connCfg.Logger = p
	connCfg.LogLevel = toPgxLogLevel(p.d.glue.Config().Logging.Level)
	poolCfg := pgx.ConnPoolConfig{
		ConnConfig:     connCfg,
		MaxConnections: numConns,
	}

	isOk := false
	defer func() {
		if !isOk {
			if p.pool != nil {
				p.pool.Close()
			}
		}
	}()

	if p.pool, err = pgx.NewConnPool(poolCfg); err != nil {
		return nil, err
	}
	if err = p.initMetadata(); err != nil {
		return nil, err
	}
	if err = p.initStatements(); err != nil {
		return nil, err
	}

	isOk = true
	return p, nil
}

type pgxUserDB struct {
	pgx *pgxImpl
}

func (d *pgxUserDB) Exists(u []byte) bool {
	// TODO/perf: If the database is both the user db and the spool this
	// check can be skipped, but bad things will happen if the calling code
	// changes.
	return d.getAuthKey(u) != nil
}

func (d *pgxUserDB) IsValid(u []byte, k wire.PublicKey) bool {
	dbKey := d.getAuthKey(u)
	if dbKey == nil {
		return false
	}
	return dbKey.Equal(k)
}

func (d *pgxUserDB) getAuthKey(u []byte) wire.PublicKey {
	var raw []byte
	if err := d.pgx.pool.QueryRow(pgxTagUserGetAuthKey, u).Scan(&raw); err != nil {
		d.pgx.d.log.Debugf("user_get_authentication_key() failed: %v", err)
		return nil
	}

	pk, err := wire.DefaultScheme.UnmarshalBinaryPublicKey(raw)
	if err != nil {
		d.pgx.d.log.Warningf("Failed to deserialize authentication key for user '%v': %v", utils.ASCIIBytesToPrintString(u), err)
		return nil
	}

	return pk
}

func (d *pgxUserDB) Add(u []byte, k wire.PublicKey, update bool) error {
	_, err := d.pgx.pool.Exec(pgxTagUserSetAuthKey, u, k.Bytes(), update)
	if err != nil && isPgNoDataFound(err) {
		return userdb.ErrNoSuchUser
	}
	return err
}

func (d *pgxUserDB) SetIdentity(u []byte, k wire.PublicKey) error {
	var kBytes []byte
	if k != nil {
		kBytes = k.Bytes()
	}

	if _, err := d.pgx.pool.Exec(pgxTagUserSetIdentKey, u, kBytes); err != nil {
		if isPgNoDataFound(err) {
			return userdb.ErrNoSuchUser
		}
		return err
	}
	return nil
}

func (d *pgxUserDB) Link(u []byte) (wire.PublicKey, error) {
	key := d.getAuthKey(u)
	if key == nil {
		return nil, userdb.ErrNoSuchUser
	}
	return key, nil
}

func (d *pgxUserDB) Identity(u []byte) (wire.PublicKey, error) {
	var raw []byte
	if err := d.pgx.pool.QueryRow(pgxTagUserGetIdentKey, u).Scan(&raw); err != nil {
		if isPgNoDataFound(err) {
			return nil, userdb.ErrNoSuchUser
		}
		return nil, err
	}
	if raw == nil {
		return nil, userdb.ErrNoIdentity
	}

	pk, err := wire.DefaultScheme.UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

func (d *pgxUserDB) Remove(u []byte) error {
	return d.pgx.doUserDelete(u)
}

func (d *pgxUserDB) Close() {
	// Nothing to do.
}

func newPgxUserDB(p *pgxImpl) *pgxUserDB {
	return &pgxUserDB{
		pgx: p,
	}
}

type pgxSpool struct {
	pgx *pgxImpl
}

func (s *pgxSpool) StoreMessage(u, msg []byte) error {
	return s.doStore(u, nil, msg)
}

func (s *pgxSpool) StoreSURBReply(u []byte, id *[sConstants.SURBIDLength]byte, msg []byte) error {
	if id == nil {
		return fmt.Errorf("pgx/spool: SURBReply is missing ID")
	}
	return s.doStore(u, id[:], msg)
}

func (s *pgxSpool) doStore(u, id, msg []byte) error {
	_, err := s.pgx.pool.Exec(pgxTagSpoolStore, u, id, msg)
	return err
}

func (s *pgxSpool) Get(u []byte, advance bool) (msg, surbID []byte, remaining int, err error) {
	if err = s.pgx.pool.QueryRow(pgxTagSpoolGet, u, advance).Scan(&msg, &surbID, &remaining); err != nil {
		s.pgx.d.log.Debugf("spool_get() failed: %v", err)
		return
	}
	return
}

func (s *pgxSpool) Remove(u []byte) error {
	// Removal is handled by removing from the UserDB, iff the database
	// is acting as both.
	if !s.pgx.IsSpoolOnly() {
		return nil
	}

	return s.pgx.doUserDelete(u)
}

func (s *pgxSpool) VacuumExpired(udb userdb.UserDB, ignoreIdentities map[[sConstants.RecipientIDLength]byte]interface{}) error {
	panic("failure! VacuumExpired not implemented for pgxSpool :(")
	return nil // XXX *le sigh* implement me
}

func (s *pgxSpool) Vacuum(udb userdb.UserDB) error {
	// This never needs to happen iff the database is acting as both the
	// UserDB and spool.
	if !s.pgx.IsSpoolOnly() {
		return nil
	}

	s.pgx.d.log.Errorf("Vacuum() not supported yet.") // TODO
	return nil
}

func (s *pgxSpool) Close() {
	// Nothing to do.
}

func newPgxSpool(p *pgxImpl) *pgxSpool {
	return &pgxSpool{
		pgx: p,
	}
}

func toPgxLogLevel(cfgLevel string) pgx.LogLevel {
	switch cfgLevel {
	case "ERROR":
		return pgx.LogLevelError
	case "WARNING", "NOTICE", "INFO":
		// pgx.LogLevelInfo is unsafe for user privacy, so don't expose that
		// unless debugging is enabled.
		return pgx.LogLevelWarn
	case "DEBUG":
		return pgx.LogLevelDebug
	default:
		panic("BUG: Invalid log level in toPgxLogLevel()")
	}
}

func isPgNoDataFound(err error) bool {
	if pgxErr, ok := err.(pgx.PgError); ok {
		if pgxErr.Code == pgCodeNoDataFound {
			return true
		}
	}
	if err == pgx.ErrNoRows { // Treat ErrNoRows as `no_data_found`.
		return true
	}
	return false
}
