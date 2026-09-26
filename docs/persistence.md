# Persistence contracts

The executable [integration example](../examples/integration) owns accounts,
one-time ceremony storage, credential storage and sessions. Root APIs perform no
I/O. `CredentialRecord.Descriptor()` copies transport hints;
`CredentialUpdate.ApplyTo(record)` compares the credential ID and all four
previous values, applies only changed fields to a copy, and validates the result.
It must run under the application's lock or equivalent database transaction.
It accepts updates from successful verification, not client-authored updates.

An invalid source record returns `ErrInvalidCredentialRecord`. A mismatched ID or
previous value returns `ErrCredentialUpdateConflict`. An invalid resulting record
returns `ErrInvalidCredentialUpdate`, wrapping the record validation cause. Error
returns contain no partial record. These helpers preserve explicit counter policy,
including authorized counter rollback; they do not make risk decisions.

## Encoding and ownership

| Value                    | Use                                                        |
| ------------------------ | ---------------------------------------------------------- |
| Root options and records | Typed application/protocol values                          |
| `browser` DTOs           | Browser-facing JSON only                                   |
| `storage/json` envelopes | Complete trusted server-side state and credential encoding |

Ordinary `encoding/json` marshaling of a root `Challenge` produces `{}` without
an error because its bytes are private. Marshaling a root state directly therefore
loses required fields. Use `MarshalRegistrationState`, `MarshalAuthenticationState`
and `MarshalCredentialRecord`, then their corresponding unmarshal functions.
Credential restoration takes the selected COSE decoder. None of these functions
provide encryption, integrity protection, storage I/O or replay prevention.

The integration example stores encoded byte slices, copies them at storage
boundaries, and restores them before use. Ceremony entries additionally bind
operation kind, initiating browser session, optional account and expiry. For
registration, recheck account authorization at finish; consume only matching
bindings, then parse the credential response. Once consumed, malformed responses
and failed verification require a new attempt. Never trust the response's user
handle or ID before verification; they are lookup hints.

## PostgreSQL reference schema

The SQL below is PostgreSQL-dialect reference material, not a database adapter or
live-database-tested code. Positional parameters come from trusted application
state. This example uses a global credential ID uniqueness constraint. Deployments
with a different tenant boundary must define that boundary explicitly.

```sql
CREATE TABLE webauthn_credentials (
    credential_id bytea PRIMARY KEY,
    rp_id text NOT NULL,
    user_handle bytea NOT NULL,
    record_json bytea NOT NULL,
    sign_count bigint NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
    backup_state boolean NOT NULL,
    uv_initialized boolean NOT NULL,
    attachment text NOT NULL DEFAULT '',
    row_version bigint NOT NULL DEFAULT 1 CHECK (row_version > 0)
);
CREATE INDEX webauthn_credentials_owner
    ON webauthn_credentials (rp_id, user_handle);

CREATE TABLE webauthn_ceremonies (
    id text PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('registration', 'authentication')),
    browser_session text NOT NULL,
    account_handle bytea,
    expires_at timestamptz NOT NULL,
    state_json bytea NOT NULL
);
```

`record_json` is the versioned credential envelope. Its mutable fields are
mirrored in comparison columns. Insert and update both representations together;
when loading, decode the envelope and verify its identity and mirrored fields
against the selected row before verification. Do not silently repair disagreement.
Use a non-null empty string for unknown attachment and SQL NULL for an absent
ceremony account. Match application expiry precision to PostgreSQL precision, or
store expiry separately at full precision; do not compare a truncated database
value to a nanosecond envelope timestamp as if they were identical.

## Unique insertion and lookup

After registration verification and application acceptance, insert all fields
from the verified record and `MarshalCredentialRecord(record)`:

```sql
INSERT INTO webauthn_credentials
    (credential_id, rp_id, user_handle, record_json,
     sign_count, backup_state, uv_initialized, attachment)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (credential_id) DO NOTHING
RETURNING credential_id;
```

No returned row means a duplicate, including a credential owned by another
account. Never overwrite or reassign that row. Account-scoped lookup uses ID,
expected user handle and configured RP ID together:

```sql
SELECT record_json, row_version, credential_id, rp_id, user_handle,
       sign_count, backup_state, uv_initialized, attachment
FROM webauthn_credentials
WHERE credential_id = $1 AND user_handle = $2 AND rp_id = $3;
```

## Atomic ceremony consumption

Use one statement; a separate read and delete permits replay. Parameters are ID,
initiating session, expected kind, whether to check the account, and the expected
account handle. The account-check switch is selected by application code:
registration checks the currently authorized account, while login obtains its
account binding from consumed trusted state.

```sql
DELETE FROM webauthn_ceremonies
WHERE id = $1 AND browser_session = $2 AND kind = $3
  AND (NOT $4::boolean OR account_handle IS NOT DISTINCT FROM $5::bytea)
  AND expires_at > CURRENT_TIMESTAMP
RETURNING state_json, account_handle, expires_at;
```

No returned row means missing, expired, already consumed or mismatched state.
Return a generic request failure. Clean up expired entries separately. Complete
the consumption transaction before parsing/verification; a later failure must
not roll it back and restore reusable state. Validate the decoded state against
its application binding. Set capacity and rate limits in application storage and
transport.

## Conditional credential update

Run application risk policy first. Compute `next` from the loaded snapshot with
`result.Update.ApplyTo(snapshot)` and encode it. The query below applies the same
four-field predicate and changed flags atomically. Parameters:

- `$1`: credential ID; `$2`: encoded next record;
- `$3/$4`: sign-count changed/new; `$5/$6`: backup-state changed/new;
- `$7/$8`: UV-initialized changed/new; `$9/$10`: attachment changed/new;
- `$11..$14`: previous sign count, backup state, UV initialization, attachment;
- `$15`: application row version from the lookup.

```sql
UPDATE webauthn_credentials
SET record_json = $2,
    sign_count = CASE WHEN $3 THEN $4 ELSE sign_count END,
    backup_state = CASE WHEN $5 THEN $6 ELSE backup_state END,
    uv_initialized = CASE WHEN $7 THEN $8 ELSE uv_initialized END,
    attachment = CASE WHEN $9 THEN $10 ELSE attachment END,
    row_version = row_version + 1
WHERE credential_id = $1
  AND sign_count = $11 AND backup_state = $12
  AND uv_initialized = $13 AND attachment = $14
  AND row_version = $15
RETURNING row_version;
```

Require exactly one returned row. Zero rows means conflict: do not create a
session, overwrite the record or retry the same verified update unconditionally.
Require a new ceremony or an explicit application re-verification strategy.
Database errors likewise prevent session creation. The next envelope must be
computed from the same snapshot and update used for the predicate and SET values.

The row version is an optional application addition. Without it, the library's
four-field comparison accepts no-op updates and cannot detect intervening writes
that restore the same values. Zero counters still require all comparisons. The
memory example deliberately increments a row version even for no-op updates, and
its concurrency tests distinguish this from `ApplyTo` value comparisons.

Create the application session only after the update transaction commits. If
session creation subsequently fails, keep the credential update and require a
fresh login attempt. A session failure must not undo ceremony consumption.
