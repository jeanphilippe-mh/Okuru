package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"path/filepath"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
)

var (
	errPublicationIsolated = errors.New("publication destination already exists")
	errPublicationRejected = errors.New("publication failed Redis admission")
)

const journalDirName = ".okuru-publications"
const intentFileName = "intent.json"
const witnessName = "archive"

// The intent contains only identifiers, already-encrypted Redis fields and
// the creator-encrypted result. Recovery does not need any client secret.
type UploadPublication struct {
	Session, FileID, PasswordID, Format                    string
	FileCipher, PasswordCipher, Result, ConfirmationDigest []byte
	TTLSeconds, Views                                      int
	Deletable                                              bool
}

func PrepareUploadRecords(session string, options *DirectFileMetadata, secret, format string) (*UploadPublication, string, string, error) {
	if !canonicalArchiveID(session) || options == nil || ValidateAPILimits(options.TTLSeconds, options.Views) != nil {
		return nil, "", "", errors.New("invalid publication options")
	}
	p := &UploadPublication{Session: session, FileID: uuid.NewString(), TTLSeconds: options.TTLSeconds, Views: options.Views, Deletable: options.Deletable, Format: format}
	value, err := fileMetadataSecret(secret, options.Password != "", format)
	if err != nil {
		return nil, "", "", err
	}
	var key string
	p.FileCipher, key, err = Encrypt(value)
	if err != nil {
		return nil, "", "", err
	}
	fileToken := p.FileID + TOKEN_SEPARATOR + key
	var passwordToken string
	if options.Password != "" {
		p.PasswordID = uuid.NewString()
		p.PasswordCipher, key, err = Encrypt(options.Password)
		if err != nil {
			return nil, "", "", err
		}
		passwordToken = p.PasswordID + TOKEN_SEPARATOR + key
	}
	return p, fileToken, passwordToken, nil
}

// The hard link already exists under a private witness when this transaction
// executes. Check all types/keys before writes: Redis scripts do not roll back.
var commitUploadPublication = redis.NewScript(4, UploadReadyLua+`
local session,idx,file,password=unpack(KEYS)
local sid,fid,ttl,views,deletable,format,fileToken,pid,passToken,result,digest,maxkeys=unpack(ARGV)
local state=checkUploadReady(session,fid)
if state=='already_ready' then return 2 end
if state then return -1 end
local it=redis.call('TYPE',idx).ok
if it~='none' and it~='zset' then return -2 end
if redis.call('EXISTS',file)~=0 or (pid~='' and redis.call('EXISTS',password)~=0) then return -2 end
if pid~='' and redis.call('DBSIZE')+2>tonumber(maxkeys) then return -3 end
local t=redis.call('TIME')
local now=t[1]*1000+math.floor(t[2]/1000)
local expires=now+tonumber(ttl)*1000
redis.call('HSET',file,'token',fileToken,'views',views,'views_count',0,'deletable',deletable,'provided',pid~='' and '1' or '0','provided_key',pid,'archive_format',format,'confirmation_digest',digest)
redis.call('PEXPIREAT',file,expires)
if pid~='' then redis.call('HSET',password,'token',passToken,'views',views,'views_count',0,'deletable',0); redis.call('PEXPIREAT',password,expires) end
applyUploadReady(session,idx,sid,result,now,expires)
return 1`)

func publicationRoot() (string, error) {
	root, err := stagingRoot(FILEFOLDER)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, journalDirName)
	if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("invalid private publication directory")
	}
	return path, nil
}

func syncPublicationDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}

func (p *UploadPublication) Save(ctx context.Context, bearer, archive string) (bool, error) {
	root, err := publicationRoot()
	if err != nil {
		return false, err
	}
	if !canonicalArchiveID(p.FileID) || !canonicalArchiveID(p.Session) {
		return false, errors.New("invalid publication identifier")
	}
	dir := filepath.Join(root, p.FileID)
	if err := os.Mkdir(dir, 0700); err != nil {
		return false, err
	}
	retained := false
	defer func() {
		if !retained {
			_ = os.RemoveAll(dir)
		}
	}()
	if err = os.Link(archive, filepath.Join(dir, witnessName)); err != nil {
		return false, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "intent.tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false, err
	}
	encErr := json.NewEncoder(f).Encode(p)
	if err = errors.Join(encErr, f.Sync(), f.Close()); err != nil {
		return false, err
	}
	if err = os.Rename(filepath.Join(dir, "intent.tmp"), filepath.Join(dir, intentFileName)); err != nil {
		return false, err
	}
	if err = errors.Join(syncPublicationDir(dir), syncPublicationDir(root)); err != nil {
		return false, err
	}
	// A lost Redis reply has an unknown outcome. Preserve the journal from
	// here until reconciliation can prove the result.
	retained = true
	if err = BindUploadPublication(ctx, p.Session, bearer, p.FileID); err != nil {
		return true, err
	}
	return true, p.finish(ctx, dir)
}

func (p *UploadPublication) finish(ctx context.Context, dir string) error {
	sess, index := UploadSessionRedisKeys(p.Session)
	conn, err := NewPool().GetContext(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	values, err := redis.Strings(redis.DoContext(conn, ctx, "HMGET", sess, "state", "publication_id"))
	if err != nil {
		return err
	}
	if len(values) != 2 {
		return errors.New("invalid publication state")
	}
	if values[1] != p.FileID || values[0] != "finalizing" {
		if values[1] == p.FileID && values[0] == "ready" {
			return os.RemoveAll(dir)
		}
		// The creator receipt can expire earlier than a published share.
		// Confirm the durable encrypted file record before undoing a stale intent.
		stored, lookupErr := redis.Bytes(redis.DoContext(conn, ctx, "HGET", REDIS_PREFIX+"file_"+p.FileID, "token"))
		if lookupErr != nil && !errors.Is(lookupErr, redis.ErrNil) {
			return lookupErr
		}
		if len(stored) > 0 && bytes.Equal(stored, p.FileCipher) {
			return os.RemoveAll(dir)
		}
		// A completed/expired or never-bound intent may only remove the file
		// it can identify by its own still-present hard link.
		if err = removeOwnedPublication(p.FileID, dir); err != nil {
			return err
		}
		return os.RemoveAll(dir)
	}
	witness := filepath.Join(dir, witnessName)
	dest := filepath.Join(FILEFOLDER, p.FileID+".zip")
	if err = os.Link(witness, dest); err != nil {
		if !os.IsExist(err) {
			return err
		}
		same, err := samePublicationFile(witness, dest)
		if err != nil {
			return err
		}
		if !same {
			if err = markPublicationCollision(p.FileID); err != nil {
				return err
			}
			if err = InterruptUploadPublication(ctx, p.Session, p.FileID); err != nil {
				return err
			}
			if err = os.RemoveAll(dir); err != nil {
				return err
			}
			return errPublicationIsolated
		}
	}
	if err = syncPublicationDir(FILEFOLDER); err != nil {
		return err
	}
	maxKeys, err := redisSecretMaxKeys()
	if err != nil {
		return err
	}
	code, err := redis.Int(commitUploadPublication.DoContext(ctx, conn, sess, index, REDIS_PREFIX+"file_"+p.FileID, REDIS_PREFIX+p.PasswordID, p.Session, p.FileID, p.TTLSeconds, p.Views, p.Deletable, p.Format, p.FileCipher, p.PasswordID, p.PasswordCipher, p.Result, p.ConfirmationDigest, maxKeys))
	if err != nil {
		return err
	}
	if code != 1 && code != 2 {
		if code == -2 || code == -3 {
			if err = InterruptUploadPublication(ctx, p.Session, p.FileID); err != nil {
				return err
			}
			if err = removeOwnedPublication(p.FileID, dir); err != nil {
				return err
			}
			if err = os.RemoveAll(dir); err != nil {
				return err
			}
			return errPublicationRejected
		}
		return errors.New("publication could not commit")
	}
	return os.RemoveAll(dir)
}

func samePublicationFile(a, b string) (bool, error) {
	first, err := os.Lstat(a)
	if err != nil {
		return false, err
	}
	second, err := os.Lstat(b)
	if err != nil {
		return false, err
	}
	return first.Mode().IsRegular() && second.Mode().IsRegular() && os.SameFile(first, second), nil
}

func removeOwnedPublication(id, dir string) error {
	dest := filepath.Join(FILEFOLDER, id+".zip")
	if _, err := os.Lstat(dest); os.IsNotExist(err) {
		return nil
	}
	same, err := samePublicationFile(filepath.Join(dir, witnessName), dest)
	if err != nil {
		return err
	}
	if !same {
		return markPublicationCollision(id)
	}
	return os.Remove(dest)
}

func markPublicationCollision(id string) error {
	root, err := publicationRoot()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root, "collision-"+id), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close(), syncPublicationDir(root))
}

// The cleaner calls this after first observing the file, before removing it.
// A witness is created before the public hard link and survives until Redis commit.
func guardedUploadPublication(id string) (bool, error) {
	for _, name := range []string{id, "collision-" + id} {
		_, err := os.Lstat(filepath.Join(FILEFOLDER, journalDirName, name))
		if err == nil {
			return true, nil
		}
		if !os.IsNotExist(err) {
			return false, err
		}
	}
	return false, nil
}

func ReconcileUploadPublications(ctx context.Context) error {
	root, err := publicationRoot()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !canonicalArchiveID(entry.Name()) {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		f, err := os.Open(filepath.Join(dir, intentFileName))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		var p UploadPublication
		err = json.NewDecoder(io.LimitReader(f, 256<<10)).Decode(&p)
		err = errors.Join(err, f.Close())
		if err != nil || p.FileID != entry.Name() || !canonicalArchiveID(p.Session) || (p.PasswordID != "" && !canonicalArchiveID(p.PasswordID)) {
			return errors.New("invalid publication journal")
		}
		unlock, err := LockUploadSession(p.Session)
		if err != nil {
			_, code := UploadSessionHTTPError(err)
			if code == "busy" {
				continue
			}
			return err
		}
		err = p.finish(ctx, dir)
		unlock()
		if errors.Is(err, errPublicationIsolated) || errors.Is(err, errPublicationRejected) {
			log.WithField("archive", p.FileID).Warn(err.Error())
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}
