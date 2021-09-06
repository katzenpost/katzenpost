/*
 * create_databse-postgresql.sql: Postgresql database creation.
 * Copyright (C) 2018  Yawning Angel.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

-- Tweak some behavior that people may be adding to their psqlrc.
\set ON_ERROR_STOP 'on'
\set ON_ERROR_ROLLBACK 'off'

-- Handle the arguments and apply sensible defaults if required.
--
--  - spoolOnly - (boolean) Set to true iff the database will only be used
--                for the spool (and not the authentication database).
--
-- TODO: There is probably a smarter way to handle this, fuck if I know, the
-- last time I had to use SQL was with MySQL 3.22.x.
\set spoolOnly :spoolOnly
SELECT CASE
  WHEN :'spoolOnly' = ':spoolOnly' THEN 'false'
  ELSE :'spoolOnly'
END::boolean as "spoolOnly" \gset
SET katzenpost.spool_only = :spoolOnly;

BEGIN;
  DO $$
  DECLARE
    pgsql_version  integer := current_setting('server_version_num')::integer;
    schema_version smallint := 0;
    spool_only     boolean := current_setting('katzenpost.spool_only')::boolean;
  BEGIN
    -- Ensure that Postgresql is sufficiently recent.
    --
    --  - INSERT ... ON CONFLICT [UPDATE, DO NOTHING] (>= 9.5).
    IF pgsql_version < 90500 THEN
      RAISE 'Insufficiently recent database: %', pgsql_version USING HINT = '9.5 or newer is requred';
    END IF;

    -- Write the database metadata.
    CREATE TABLE metadata (
      schema_version smallint NOT NULL,
      spool_only     boolean NOT NULL
    );
    INSERT INTO metadata(schema_version, spool_only) VALUES (schema_version, spool_only);

    -- Create the user table.
    CREATE TABLE users (
      user_id    bigserial PRIMARY KEY,
      user_name  bytea NOT NULL UNIQUE
    );
    IF spool_only = false THEN
      -- If the user table is an actual user database, then it needs a
      -- column for the user's authentication key and identity key.
      ALTER TABLE users ADD COLUMN authentication_key bytea NOT NULL;
      ALTER TABLE users ADD COLUMN identity_key bytea;
    END IF;

    -- Create the spool table.
    CREATE TABLE spool (
      message_id   bigserial PRIMARY KEY,
      user_id      bigint REFERENCES users ON DELETE CASCADE,
      surb_id      bytea,
      message_body bytea NOT NULL
    );
    CREATE INDEX ON spool(user_id);

    -- Create the functions.
    --
    -- All Katzenpost server -> RDBMS interactions will happen via functions
    -- so that:
    --
    --  - The user the server uses can have an extremely limit set of access
    --    priviledges to prevent horrific things from happening.
    --  - People that are good at database development can contribute without
    --    having to deal with the server code at all.

    CREATE FUNCTION metadata_get() RETURNS record AS $METADATA_GET$
    DECLARE
      ret record;
    BEGIN
      SELECT * INTO STRICT ret FROM metadata;
      RETURN ret;
    END $METADATA_GET$ LANGUAGE plpgsql STABLE;

    IF spool_only = false THEN

      CREATE FUNCTION user_get_authentication_key(user_name bytea) RETURNS bytea AS $USER_GET_AUTH$
      DECLARE
        ret bytea;
      BEGIN
        SELECT authentication_key INTO STRICT ret FROM users WHERE users.user_name = $1;
        RETURN ret;
      END $USER_GET_AUTH$ LANGUAGE plpgsql STABLE;

      CREATE FUNCTION user_set_authentication_key(user_name bytea, authentication_key bytea, is_update boolean) RETURNS void AS $USER_SET_AUTH$
      BEGIN
        IF $3 = true THEN
          UPDATE users SET authentication_key = $2 WHERE user_name = $1;
          IF NOT FOUND THEN
            RAISE SQLSTATE 'P0002'; -- `no_data_found`
          END IF;
        ELSE
          INSERT INTO users(user_id, user_name, authentication_key) VALUES (DEFAULT, $1, $2);
        END IF;
      END $USER_SET_AUTH$ LANGUAGE plpgsql;

      CREATE FUNCTION user_get_identity_key(user_name bytea) RETURNS bytea AS $USER_GET_IDENT$
      DECLARE
        ret bytea;
      BEGIN
        SELECT identity_key INTO STRICT ret FROM users WHERE users.user_name = $1;
        RETURN ret;
      END $USER_GET_IDENT$ LANGUAGE plpgsql STABLE;

      CREATE FUNCTION user_set_identity_key(user_name bytea, identity_key bytea) RETURNS void AS $USER_SET_IDENT$
      BEGIN
        UPDATE users SET identity_key = $2 WHERE users.user_name = $1;
        IF NOT FOUND THEN
          RAISE SQLSTATE 'P0002'; -- `no_data_found`
        END IF;
      END $USER_SET_IDENT$ LANGUAGE plpgsql;

      -- user_delete() is defined as a spool database routine, because it is
      -- what is used to remove the user's spool entries.
    END IF;

    CREATE FUNCTION user_delete(user_name bytea) RETURNS void AS $USER_DELETE$
    DECLARE
      deleted integer;
    BEGIN
      DELETE FROM users WHERE users.user_name = $1 RETURNING 1 INTO STRICT deleted;
    END $USER_DELETE$ LANGUAGE plpgsql;

    CREATE FUNCTION spool_get(user_name bytea, advance boolean) RETURNS record AS $SPOOL_GET$
    DECLARE
      spool_cursor refcursor;
      spool_row    record;
      surb_id      bytea;
      message_body bytea;
      remaining    integer;
      ret          record;
    BEGIN
      -- Note: If there ever are going to be multiple simultanious accesses to
      -- a given user's spool (currently prohibited by the caller), then this
      -- probably needs to acquire an advisory lock at the begining.
      OPEN spool_cursor NO SCROLL FOR SELECT * from spool WHERE user_id = (SELECT user_id FROM users WHERE users.user_name = $1) ORDER BY message_id FOR UPDATE;

      -- Set the output to something sane.
      ret := (NULL::bytea, NULL::bytea, 0);

      -- Grab the first message.
      FETCH spool_cursor INTO spool_row;
      IF NOT FOUND THEN
        -- The user's spool is empty, bail out.
        RETURN ret;
      ELSIF $2 = true THEN
        -- Delete the first row, and advance the cursor.
        DELETE FROM spool WHERE CURRENT OF spool_cursor;
        FETCH spool_cursor INTO spool_row;
        IF NOT FOUND THEN
          -- The delete drained the user's spool, bail out.
          RETURN ret;
        END IF;
      END IF;

      -- Copy the (new) head of the user's spool into the output.
      surb_id := spool_row.surb_id;
      message_body := spool_row.message_body;

      -- Figure out if there is at least one more message in the user's spool.
      MOVE spool_cursor;
      IF FOUND THEN
        -- At least one more message in the user's spool.
        --
        -- TODO: It's probably better if this returns a more accurate count,
        -- but it is adequate to return a "yes/no".
        remaining := 1;
      ELSE
        remaining := 0;
      END IF;

      ret := (message_body, surb_id, remaining);
      RETURN ret;
    END $SPOOL_GET$ LANGUAGE plpgsql;

    IF spool_only = false THEN

      CREATE FUNCTION spool_store(user_name bytea, surb_id bytea, msg bytea) RETURNS void AS $SPOOL_STORE$
      BEGIN
        INSERT INTO spool(message_id, user_id, surb_id, message_body) VALUES (DEFAULT, (SELECT user_id FROM users WHERE users.user_name = $1), $2, $3);
      END $SPOOL_STORE$ LANGUAGE plpgsql;

    ELSE

      CREATE FUNCTION spool_store(user_name bytea, surb_id bytea, msg bytea) RETURNS void AS $SPOOL_STORE$
      BEGIN
        -- Can't use RETURNING to get the user_id, because when nothing is
        -- updated, nothing is returned.
        INSERT INTO users(user_id, user_name) VALUES (DEFAULT, $1) ON CONFLICT DO NOTHING;
        INSERT INTO spool(message_id, user_id, surb_id, message_body) VALUES (DEFAULT, (SELECT user_id FROM users WHERE users.user_name = $1), $2, $3);
      END $SPOOL_STORE$ LANGUAGE plpgsql;

    END IF;

  END $$ LANGUAGE plpgsql;

  -- Dump the created tables.
  \d users
  \d spool
  \df

COMMIT;
