package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
)

func TestUploadSessionSlotAndRedisBudgets(t *testing.T) {
	c, r, m := sessionTestSetup(t)
	ctx := context.Background()
	r.RemoteAddr = "127.0.0.1:10000"
	id, bearer := uuid.NewString(), newUploadSecret()
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "128")
	if _, _, err := PrepareFileUploadSession(ctx, r, id, bearer, m); err != uploadSessionError("redis_capacity") {
		t.Fatalf("missing safety reserve: %v", err)
	}
	if count, err := redis.Int(c.Do("EXISTS", REDIS_PREFIX+"upload_v2_"+id)); err != nil || count != 0 {
		t.Fatal(count, err)
	}
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "100000")
	var ids, keys []string
	for n := 0; n < 4; n++ {
		id, token := uuid.NewString(), newUploadSecret()
		if _, _, err := PrepareFileUploadSession(ctx, r, id, token, m); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		keys = append(keys, token)
	}
	if _, _, err := PrepareFileUploadSession(ctx, r, uuid.NewString(), newUploadSecret(), m); err != uploadSessionError("capacity") {
		t.Fatalf("global active limit: %v", err)
	}
	if err := AbortFileUploadSession(ctx, ids[0], keys[0]); err != nil {
		t.Fatal(err)
	}
	if err := AbortFileUploadSession(ctx, ids[0], keys[0]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareFileUploadSession(ctx, r, uuid.NewString(), newUploadSecret(), m); err != nil {
		t.Fatal(err)
	}
}

func TestUploadSessionExpirationAndPartBudget(t *testing.T) {
	c, r, m := sessionTestSetup(t)
	ctx := context.Background()
	id, bearer := uuid.NewString(), newUploadSecret()
	s, _, err := PrepareFileUploadSession(ctx, r, id, bearer, m)
	if err != nil {
		t.Fatal(err)
	}
	if owned, err := UploadSessionOwnsParts(ctx, id); !owned || err != nil {
		t.Fatal(owned, err)
	}
	key, _ := UploadSessionRedisKeys(id)
	if _, err = c.Do("HSET", key, "parts", 2048); err != nil {
		t.Fatal(err)
	}
	if err := CommitUploadOffset(ctx, id, bearer, 0, 0, 1); err != uploadSessionError("part_limit") {
		t.Fatalf("part limit: %v", err)
	}
	if off, err := ConfirmedUploadOffset(ctx, id, bearer, 0); err != nil || off != 0 {
		t.Fatal(off, err)
	}
	if err := CommitUploadOffset(ctx, id, bearer, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := AbortFileUploadSession(ctx, id, s.StatusToken); err != uploadSessionError("not_found") {
		t.Fatal(err)
	}
	if _, err = c.Do("HSET", key, "until", time.Now().Add(-time.Second).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := AuthorizeUploadSession(ctx, id, bearer, false); err != uploadSessionError("expired") {
		t.Fatal(err)
	}
	if st, err := AuthorizeUploadSession(ctx, id, s.StatusToken, true); err != nil || st.State != "expired" {
		t.Fatal(err)
	}
	if owned, err := UploadSessionOwnsParts(ctx, id); owned || err != nil {
		t.Fatal(owned, err)
	}
}

func TestUploadSessionConcurrentReplay(t *testing.T) {
	_, r, m := sessionTestSetup(t)
	ctx := context.Background()
	id, bearer := uuid.NewString(), newUploadSecret()
	type attempt struct {
		created bool
		session *UploadSession
		err     error
	}
	results := make(chan attempt, 8)
	for n := 0; n < cap(results); n++ {
		go func() {
			s, created, err := PrepareFileUploadSession(ctx, r, id, bearer, m)
			results <- attempt{created, s, err}
		}()
	}
	var token string
	var created int
	for i := 0; i < cap(results); i++ {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if token == "" {
			token = result.session.StatusToken
		}
		if token != result.session.StatusToken {
			t.Fatal("simultaneous retry returned a different watcher key")
		}
		if result.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("new sessions reported: %d", created)
	}
}

func TestUploadSessionOwnerExclusion(t *testing.T) {
	root := t.TempDir()
	first, err := AcquireUploadSessionOwner(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	if _, err := AcquireUploadSessionOwner(root); err == nil {
		t.Fatal("second live owner admitted")
	}
	id := uuid.NewString()
	release, err := LockUploadSession(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockUploadSession(id); err != uploadSessionError("busy") {
		t.Fatal(err)
	}
	release()
	release()
	again, err := LockUploadSession(id)
	if err != nil {
		t.Fatal(err)
	}
	again()
	first()
	second, err := AcquireUploadSessionOwner(root)
	if err != nil {
		t.Fatal(err)
	}
	second()
}

func TestUploadSessionManifestContract(t *testing.T) {
	const required = `"mode":"blocks","files":[{"name":"empty","size":0}]`
	m, err := ParseUploadManifest(strings.NewReader("{"+required+"}"), 5)
	if err != nil || m.Metadata.TTLSeconds != 3600 || m.Metadata.Views != 1 || m.Metadata.Files[0].Size != 0 {
		t.Fatalf("defaults: %#v %v", m, err)
	}
	cases := []string{
		"{" + required + `,"ttl_seconds":0}`,
		"{" + required + `,"views":0}`,
		"{" + required + `,"views":null}`,
		"{" + required + `,"mode":"multipart"}`,
		"{" + required + `,"password":null}`,
		"{" + required + `,"extra":1}`,
		`{"mode":"blocks","files":[]}`,
		`{"mode":"blocks","files":[{"name":"a","size": 9223372036854775808}]}`,
		`{"mode":"blocks","files":[{"name":"A","size":0},{"name":"a","size":0}]}`,
		`{"mode":"blocks","files":[{"name":"a","size":1,"s\u0069ze":2}]}`,
		`{"mode":"blocks","files":[{"name":"a","size":3},{"name":"b","size":3}]}`,
	}
	for _, input := range cases {
		if _, err := ParseUploadManifest(strings.NewReader(input), 5); err == nil {
			t.Fatal("accepted invalid manifest", input)
		}
	}
	if _, err := ParseUploadManifest(strings.NewReader(strings.Repeat(" ", UploadSessionManifestLimit+1)), 1); err != uploadSessionError("too_large") {
		t.Fatal(err)
	}
}

func sessionTestSetup(t *testing.T) (redis.Conn, *http.Request, *UploadManifest) {
	t.Helper()
	c := admissionTestRedis(t)
	old := MaxFileSize
	MaxFileSize = 1000
	t.Cleanup(func() { MaxFileSize = old })
	root := t.TempDir()
	release, err := AcquireUploadSessionOwner(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	t.Setenv("OKURU_FILE_API", "true")
	t.Setenv("OKURU_UPLOAD_BLOCKS", "true")
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "100000")
	prefix := REDIS_PREFIX + "upload_v2_"
	if _, err := c.Do("HSET", prefix+"admission", "api", "open", "blocks", "open"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		keys, err := redis.Strings(c.Do("KEYS", prefix+"*"))
		if err == nil && len(keys) > 0 {
			_, _ = c.Do("DEL", redis.Args{}.AddFlat(keys)...)
		}
	})
	r := httptest.NewRequest("POST", "https://okuru.invalid/api/v2/uploads", nil)
	r.RemoteAddr = "1.1.1.1:443"
	m, err := ParseUploadManifest(strings.NewReader(`{"mode":"blocks","password":"private-password","files":[{"name":"private-name.txt","size":7}]}`), 1000)
	if err != nil {
		t.Fatal(err)
	}
	return c, r, m
}
func TestUploadSessionCapabilitiesAndPublication(t *testing.T) {
	c, r, m := sessionTestSetup(t)
	ctx := context.Background()
	id, bearer := uuid.NewString(), newUploadSecret()
	s, created, err := PrepareFileUploadSession(ctx, r, id, bearer, m)
	if err != nil || !created || s.StatusToken == "" || s.Mode != "blocks" {
		t.Fatalf("create: %v %v", created, err)
	}
	s2, created, err := PrepareFileUploadSession(ctx, r, id, bearer, m)
	if err != nil || created || s2.StatusToken != s.StatusToken {
		t.Fatalf("unstable replay: %v", err)
	}
	key, _ := UploadSessionRedisKeys(id)
	vals, err := redis.Strings(c.Do("HVALS", key))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vals {
		for _, private := range []string{"private-password", "private-name.txt", bearer, s.StatusToken} {
			if strings.Contains(v, private) {
				t.Fatal("Redis contains a private value")
			}
		}
	}
	if _, _, err := PrepareFileUploadSession(ctx, r, id, newUploadSecret(), m); err != uploadSessionError("not_found") {
		t.Fatalf("wrong creator: %v", err)
	}
	m2 := *m
	m2.Metadata.Views++
	if _, _, err := PrepareFileUploadSession(ctx, r, id, bearer, &m2); err != uploadSessionError("manifest_conflict") {
		t.Fatal(err)
	}
	watcher, err := AuthorizeUploadSession(ctx, id, s.StatusToken, true)
	if err != nil || !watcher.StatusOnly || watcher.Metadata != nil || watcher.StatusToken != "" {
		t.Fatal("watcher has creator data", err)
	}
	if _, err := ReadUploadResult(ctx, id, s.StatusToken); err != uploadSessionError("not_found") {
		t.Fatal(err)
	}
	if _, err := ReadUploadResult(ctx, id, bearer); err != uploadSessionError("not_ready") {
		t.Fatal(err)
	}
	if err := BeginMultipartAttempt(ctx, id, bearer, 7); err != uploadSessionError("wrong_mode") {
		t.Fatal(err)
	}
	if err := BeginUploadPublication(ctx, id, bearer); err != uploadSessionError("not_ready") {
		t.Fatal(err)
	}
	if err := CommitUploadOffset(ctx, id, bearer, 0, 0, 3); err != nil {
		t.Fatal(err)
	}
	if err := CommitUploadOffset(ctx, id, bearer, 0, 0, 3); err != uploadSessionError("offset_conflict") {
		t.Fatal(err)
	}
	if n, err := ConfirmedUploadOffset(ctx, id, bearer, 0); err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if err := CommitUploadOffset(ctx, id, bearer, 0, 3, 7); err != nil {
		t.Fatal(err)
	}
	if err := BeginUploadPublication(ctx, id, bearer); err != nil {
		t.Fatal(err)
	}
	if err := AbortFileUploadSession(ctx, id, bearer); err != uploadSessionError("busy") {
		t.Fatal(err)
	}
	result := []byte(`{"link":"/file/private-link"}`)
	publication := uuid.NewString()
	if err := BindUploadPublication(ctx, id, bearer, publication); err != nil {
		t.Fatal(err)
	}
	sealed, err := SealUploadResult(id, bearer, result)
	if err != nil || bytes.Contains(sealed, []byte("private-link")) {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond)
	if err := StoreSealedUploadResult(ctx, id, uuid.NewString(), sealed, deadline); err != uploadSessionError("not_ready") {
		t.Fatal(err)
	}
	if err := StoreSealedUploadResult(ctx, id, publication, sealed, deadline); err != nil {
		t.Fatal(err)
	}
	got, err := ReadUploadResult(ctx, id, bearer)
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Link      string
		ExpiresAt time.Time `json:"expires_at"`
	}
	if json.Unmarshal(got, &response) != nil || response.Link != "/file/private-link" || !response.ExpiresAt.Equal(deadline) {
		t.Fatalf("wrong published receipt: %s", got)
	}
	if _, err := ReadUploadResult(ctx, id, s.StatusToken); err != uploadSessionError("not_found") {
		t.Fatal(err)
	}
}
func TestUploadSessionHotClosureLimitsAndTerminalAccess(t *testing.T) {
	c, r, m := sessionTestSetup(t)
	ctx := context.Background()
	id, bearer := uuid.NewString(), newUploadSecret()
	s, _, err := PrepareFileUploadSession(ctx, r, id, bearer, m)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := PrepareFileUploadSession(ctx, r, uuid.NewString(), newUploadSecret(), m); err != uploadSessionError("capacity") {
		t.Fatalf("identity limit: %v", err)
	}
	c.Do("HSET", REDIS_PREFIX+"upload_v2_admission", "api", "closed")
	if _, _, err := PrepareFileUploadSession(ctx, r, uuid.NewString(), newUploadSecret(), m); err != uploadSessionError("closed") {
		t.Fatalf("closed: %v", err)
	}
	if _, created, err := PrepareFileUploadSession(ctx, r, id, bearer, m); err != nil || created {
		t.Fatalf("replay denied after closure: %v", err)
	}
	key, _ := UploadSessionRedisKeys(id)
	c.Do("HSET", key, "generation", uuid.NewString())
	if _, err := AuthorizeUploadSession(ctx, id, bearer, false); err != uploadSessionError("interrupted") {
		t.Fatalf("stale owner: %v", err)
	}
	if st, err := AuthorizeUploadSession(ctx, id, s.StatusToken, true); err != nil || st.State != "interrupted" {
		t.Fatal(err)
	}
	if _, err := AuthorizeUploadSession(ctx, id, newUploadSecret(), false); err != uploadSessionError("not_found") {
		t.Fatal(err)
	}
}
