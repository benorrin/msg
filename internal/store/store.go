// Package store is the SQLite persistence layer. The server never sees
// plaintext: entries are opaque ciphertext plus the minimum metadata needed
// for routing (channel, author, ordering).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrUsernameTaken = errors.New("username taken")
	ErrAlreadyMember = errors.New("already a member")
	ErrBadChannel    = errors.New("unknown channel")
)

// CurrentEpoch is the channel-key generation. Key rotation is not implemented
// yet, but every envelope and entry carries the epoch so it can be added
// without a format change.
const CurrentEpoch = 1

// Channel kinds. Only KindStream notifies members.
const (
	KindStream    = "stream"
	KindLinks     = "links"
	KindBookmarks = "bookmarks"
	KindFiles     = "files"
)

type Channel struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Unread int    `json:"unread"`
	LastID int64  `json:"last_id"`
}

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	EncPub    string `json:"enc_pub"`
	SignPub   string `json:"sign_pub"`
	Member    bool   `json:"member"`
	CreatedAt int64  `json:"created_at"`
}

// Envelope is the channel key sealed to one member's public key, signed by
// the member who granted access.
type Envelope struct {
	UserID    int64  `json:"user_id"`
	Epoch     int    `json:"epoch"`
	Sealed    string `json:"sealed"`
	Sig       string `json:"sig"`
	GrantedBy int64  `json:"granted_by"`
	CreatedAt int64  `json:"created_at"`
}

type Entry struct {
	ID        int64  `json:"id"`
	Channel   string `json:"channel"`
	AuthorID  int64  `json:"author_id"`
	Epoch     int    `json:"epoch"`
	CID       string `json:"cid"`
	CT        string `json:"ct"`
	Sig       string `json:"sig"`
	OriginID  *int64 `json:"origin_id,omitempty"`
	CreatedAt int64  `json:"created_at"`

	// Dup marks a row that already existed (an idempotent retry); callers
	// should not broadcast it again.
	Dup bool `json:"-"`
}

type NewEntry struct {
	Channel string
	Epoch   int
	CID     string
	CT      string
	Sig     string
}

type Store struct {
	w        *sql.DB // single writer
	r        *sql.DB // reader pool
	channels map[string]Channel
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id           INTEGER PRIMARY KEY,
	username     TEXT NOT NULL UNIQUE,
	auth_hash    TEXT NOT NULL,
	enc_pub      TEXT NOT NULL,
	sign_pub     TEXT NOT NULL,
	wrapped_keys TEXT NOT NULL,
	created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
	id   TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,
	pos  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS envelopes (
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	epoch      INTEGER NOT NULL,
	sealed     TEXT NOT NULL,
	sig        TEXT NOT NULL,
	granted_by INTEGER NOT NULL REFERENCES users(id),
	created_at INTEGER NOT NULL,
	PRIMARY KEY (user_id, epoch)
);
CREATE TABLE IF NOT EXISTS entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	channel    TEXT NOT NULL REFERENCES channels(id),
	author_id  INTEGER NOT NULL REFERENCES users(id),
	epoch      INTEGER NOT NULL,
	cid        TEXT NOT NULL,
	ct         TEXT NOT NULL,
	sig        TEXT NOT NULL,
	origin_id  INTEGER REFERENCES entries(id),
	created_at INTEGER NOT NULL,
	UNIQUE (author_id, cid)
);
CREATE INDEX IF NOT EXISTS entries_channel_id ON entries (channel, id);
CREATE TABLE IF NOT EXISTS read_marks (
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	channel TEXT NOT NULL REFERENCES channels(id),
	upto    INTEGER NOT NULL,
	PRIMARY KEY (user_id, channel)
);
`

var defaultChannels = []Channel{
	{ID: "main", Name: "main", Kind: KindStream},
	{ID: "links", Name: "links", Kind: KindLinks},
	{ID: "bookmarks", Name: "bookmarks", Kind: KindBookmarks},
	{ID: "files", Name: "files", Kind: KindFiles},
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"
	w, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	r, err := sql.Open("sqlite", dsn+"&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	r.SetMaxOpenConns(8)

	s := &Store{w: w, r: r, channels: map[string]Channel{}}
	if _, err := w.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	for i, c := range defaultChannels {
		if _, err := w.Exec(`INSERT OR IGNORE INTO channels (id,name,kind,pos) VALUES (?,?,?,?)`, c.ID, c.Name, c.Kind, i); err != nil {
			return nil, err
		}
	}
	rows, err := r.Query(`SELECT id,name,kind FROM channels ORDER BY pos`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind); err != nil {
			return nil, err
		}
		s.channels[c.ID] = c
	}
	return s, rows.Err()
}

func (s *Store) Close() error {
	s.r.Close()
	return s.w.Close()
}

// ChannelKind returns the kind of a channel, or ErrBadChannel.
func (s *Store) ChannelKind(id string) (string, error) {
	c, ok := s.channels[id]
	if !ok {
		return "", ErrBadChannel
	}
	return c.Kind, nil
}

func now() int64 { return time.Now().UnixMilli() }

// ---- users & sessions ----

// Register creates a user. If this is the very first user and bootstrap is
// non-nil, the user is also granted the channel key (they created it).
// granted reports whether the bootstrap envelope was accepted.
func (s *Store) Register(ctx context.Context, username, authHash, encPub, signPub, wrapped string, bootstrap *Envelope) (u User, granted bool, err error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return u, false, err
	}
	defer tx.Rollback()

	t := now()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (username,auth_hash,enc_pub,sign_pub,wrapped_keys,created_at) VALUES (?,?,?,?,?,?)`,
		username, authHash, encPub, signPub, wrapped, t)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return u, false, ErrUsernameTaken
		}
		return u, false, err
	}
	id, _ := res.LastInsertId()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return u, false, err
	}
	if n == 1 && bootstrap != nil {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO envelopes (user_id,epoch,sealed,sig,granted_by,created_at) VALUES (?,?,?,?,?,?)`,
			id, CurrentEpoch, bootstrap.Sealed, bootstrap.Sig, id, t); err != nil {
			return u, false, err
		}
		granted = true
	}
	if err := tx.Commit(); err != nil {
		return u, false, err
	}
	return User{ID: id, Username: username, EncPub: encPub, SignPub: signPub, Member: granted, CreatedAt: t}, granted, nil
}

// Credentials returns what login needs. Unknown users return ErrNotFound.
func (s *Store) Credentials(ctx context.Context, username string) (u User, authHash, wrapped string, err error) {
	err = s.r.QueryRowContext(ctx, `
		SELECT u.id,u.username,u.enc_pub,u.sign_pub,u.created_at,u.auth_hash,u.wrapped_keys,
		       EXISTS(SELECT 1 FROM envelopes e WHERE e.user_id=u.id)
		FROM users u WHERE u.username=?`, username).
		Scan(&u.ID, &u.Username, &u.EncPub, &u.SignPub, &u.CreatedAt, &authHash, &wrapped, &u.Member)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return
}

func (s *Store) CreateSession(ctx context.Context, tokenHash string, userID int64, expires time.Time) error {
	_, err := s.w.ExecContext(ctx, `INSERT INTO sessions (token_hash,user_id,expires_at) VALUES (?,?,?)`,
		tokenHash, userID, expires.UnixMilli())
	return err
}

func (s *Store) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) PurgeSessions(ctx context.Context) error {
	_, err := s.w.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<?`, now())
	return err
}

// SessionUser resolves a session token hash to its user.
func (s *Store) SessionUser(ctx context.Context, tokenHash string) (User, error) {
	var u User
	err := s.r.QueryRowContext(ctx, `
		SELECT u.id,u.username,u.enc_pub,u.sign_pub,u.created_at,
		       EXISTS(SELECT 1 FROM envelopes e WHERE e.user_id=u.id)
		FROM sessions s JOIN users u ON u.id=s.user_id
		WHERE s.token_hash=? AND s.expires_at>?`, tokenHash, now()).
		Scan(&u.ID, &u.Username, &u.EncPub, &u.SignPub, &u.CreatedAt, &u.Member)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return u, err
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.r.QueryContext(ctx, `
		SELECT u.id,u.username,u.enc_pub,u.sign_pub,u.created_at,
		       EXISTS(SELECT 1 FROM envelopes e WHERE e.user_id=u.id)
		FROM users u ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.EncPub, &u.SignPub, &u.CreatedAt, &u.Member); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) userBy(ctx context.Context, col string, v any) (User, error) {
	var u User
	err := s.r.QueryRowContext(ctx, `
		SELECT u.id,u.username,u.enc_pub,u.sign_pub,u.created_at,
		       EXISTS(SELECT 1 FROM envelopes e WHERE e.user_id=u.id)
		FROM users u WHERE u.`+col+`=?`, v).
		Scan(&u.ID, &u.Username, &u.EncPub, &u.SignPub, &u.CreatedAt, &u.Member)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return u, err
}

func (s *Store) UserByName(ctx context.Context, username string) (User, error) {
	return s.userBy(ctx, "username", username)
}

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return s.userBy(ctx, "id", id)
}

// ---- envelopes ----

func (s *Store) Envelope(ctx context.Context, userID int64) (*Envelope, error) {
	var e Envelope
	err := s.r.QueryRowContext(ctx,
		`SELECT user_id,epoch,sealed,sig,granted_by,created_at FROM envelopes WHERE user_id=? AND epoch=?`,
		userID, CurrentEpoch).
		Scan(&e.UserID, &e.Epoch, &e.Sealed, &e.Sig, &e.GrantedBy, &e.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Grant stores the channel key sealed for target. Fails if target already
// holds an envelope, so a member cannot swap another member's key.
func (s *Store) Grant(ctx context.Context, target, grantedBy int64, sealed, sig string) (*Envelope, error) {
	e := &Envelope{UserID: target, Epoch: CurrentEpoch, Sealed: sealed, Sig: sig, GrantedBy: grantedBy, CreatedAt: now()}
	_, err := s.w.ExecContext(ctx,
		`INSERT INTO envelopes (user_id,epoch,sealed,sig,granted_by,created_at) VALUES (?,?,?,?,?,?)`,
		e.UserID, e.Epoch, e.Sealed, e.Sig, e.GrantedBy, e.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrAlreadyMember
		}
		return nil, err
	}
	return e, nil
}

// ---- channels & entries ----

func (s *Store) Channels(ctx context.Context, userID int64) ([]Channel, error) {
	rows, err := s.r.QueryContext(ctx, `
		SELECT c.id,c.name,c.kind,
		  (SELECT COALESCE(MAX(id),0) FROM entries WHERE channel=c.id),
		  (SELECT COUNT(*) FROM entries e WHERE e.channel=c.id AND e.author_id<>?1
		     AND e.id > COALESCE((SELECT upto FROM read_marks r WHERE r.user_id=?1 AND r.channel=c.id),0))
		FROM channels c ORDER BY c.pos`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		var c Channel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.LastID, &c.Unread); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) MarkRead(ctx context.Context, userID int64, channel string, upto int64) error {
	if _, err := s.ChannelKind(channel); err != nil {
		return err
	}
	_, err := s.w.ExecContext(ctx, `
		INSERT INTO read_marks (user_id,channel,upto) VALUES (?,?,?)
		ON CONFLICT(user_id,channel) DO UPDATE SET upto=MAX(upto,excluded.upto)`, userID, channel, upto)
	return err
}

// AddEntries stores a primary entry and any mirrored side-channel entries in
// one transaction. Mirrors point back at the primary via origin_id. Retrying
// with the same (author, cid) is idempotent and returns the stored rows.
func (s *Store) AddEntries(ctx context.Context, author int64, primary NewEntry, mirrors []NewEntry) ([]Entry, error) {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var out []Entry
	var origin *int64
	for i, ne := range append([]NewEntry{primary}, mirrors...) {
		e, err := insertEntry(ctx, tx, author, ne, origin)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			id := e.ID
			origin = &id
		}
		out = append(out, e)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func insertEntry(ctx context.Context, tx *sql.Tx, author int64, ne NewEntry, origin *int64) (Entry, error) {
	e := Entry{Channel: ne.Channel, AuthorID: author, Epoch: ne.Epoch, CID: ne.CID, CT: ne.CT, Sig: ne.Sig, OriginID: origin, CreatedAt: now()}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO entries (channel,author_id,epoch,cid,ct,sig,origin_id,created_at) VALUES (?,?,?,?,?,?,?,?)`,
		e.Channel, e.AuthorID, e.Epoch, e.CID, e.CT, e.Sig, e.OriginID, e.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			// Retry of an earlier send: return what was stored.
			row := tx.QueryRowContext(ctx,
				`SELECT id,channel,author_id,epoch,cid,ct,sig,origin_id,created_at FROM entries WHERE author_id=? AND cid=?`,
				author, ne.CID)
			dup, err := scanEntry(row)
			dup.Dup = true
			return dup, err
		}
		return e, err
	}
	e.ID, _ = res.LastInsertId()
	return e, nil
}

type scanner interface{ Scan(...any) error }

func scanEntry(r scanner) (e Entry, err error) {
	var origin sql.NullInt64
	err = r.Scan(&e.ID, &e.Channel, &e.AuthorID, &e.Epoch, &e.CID, &e.CT, &e.Sig, &origin, &e.CreatedAt)
	if origin.Valid {
		e.OriginID = &origin.Int64
	}
	return
}

// Entries pages a channel. With after>0 it returns entries newer than after
// (ascending); otherwise the newest `limit` entries older than before
// (before==0 means newest), returned ascending.
func (s *Store) Entries(ctx context.Context, channel string, before, after int64, limit int) ([]Entry, error) {
	if _, err := s.ChannelKind(channel); err != nil {
		return nil, err
	}
	const cols = `id,channel,author_id,epoch,cid,ct,sig,origin_id,created_at`
	var rows *sql.Rows
	var err error
	if after > 0 {
		rows, err = s.r.QueryContext(ctx, `SELECT `+cols+` FROM entries WHERE channel=? AND id>? ORDER BY id LIMIT ?`, channel, after, limit)
	} else {
		if before == 0 {
			before = 1<<62 - 1
		}
		rows, err = s.r.QueryContext(ctx, `SELECT `+cols+` FROM (SELECT `+cols+` FROM entries WHERE channel=? AND id<? ORDER BY id DESC LIMIT ?) ORDER BY id`, channel, before, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
