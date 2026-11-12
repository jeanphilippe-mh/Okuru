package utils

import (
	"errors"

	"filippo.io/age"
)

// ArchiveFormatAgeUserPassword distinguishes password-protected archives whose
// metadata contains an independent random bearer authenticator, rather than an
// encrypted copy of the user's archive password. The archive is still age v1.
const ArchiveFormatAgeUserPassword = "age-user-password-v2"

var errArchivePasswordRequired = errors.New("archive password is required")
var errArchiveIdentityRequired = errors.New("an archive identity is required for unprotected files")

// fileMetadataSecret separates the file-link authenticator from the archive
// password for new explicitly password-protected files. Legacy records still
// need their original password to remain readable.
func fileMetadataSecret(password string, provided bool, archiveFormat string) (string, error) {
	if archiveFormat == ArchiveFormatAgeX25519 {
		if provided || password == "" {
			return "", errArchiveIdentityRequired
		}
		if _, err := age.ParseX25519Identity(password); err != nil {
			return "", errArchiveIdentityRequired
		}
		return password, nil
	}
	if archiveFormat != ArchiveFormatAgeUserPassword {
		return password, nil
	}
	if !provided || password == "" {
		return "", errArchivePasswordRequired
	}
	return GenerateRandomString(50)
}

// IsArchivePasswordError reports age's incorrect-passphrase result, including
// its wrapping NoIdentityMatchError. Corrupt data and cancellation remain
// distinct errors, and must not be misreported as a wrong password.
func IsArchivePasswordError(err error) bool {
	return errors.Is(err, age.ErrIncorrectIdentity)
}
