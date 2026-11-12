package utils

import (
	"errors"
	"strconv"
)

// MaxSecretBytes bounds memory and Redis use independently of the upload limit.
// The limit is measured in bytes so multibyte text cannot bypass it.
const MaxSecretBytes = 32 << 10

// MaxWebNumberBytes bounds fields before strconv can copy them into an error.
const MaxWebNumberBytes = 16

func ValidateSecretLength(secret string) error {
	if len(secret) > MaxSecretBytes {
		return errors.New("secret exceeds the maximum size")
	}
	return nil
}

func ParseWebNumber(value string) (int, error) {
	if len(value) == 0 || len(value) > MaxWebNumberBytes {
		return 0, errors.New("invalid number")
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, errors.New("invalid number")
	}
	return n, nil
}

func ValidateWebLimits(ttl, views int) error {
	if ttl < 1 || ttl > 30 {
		return errors.New("duration must be between 1 and 30")
	}
	if views < 1 || views > 100 {
		return errors.New("attempts must be between 1 and 100")
	}
	return nil
}

// API duration is expressed in seconds, unlike the web slider.
func ValidateAPILimits(ttl, views int) error {
	if ttl < 300 || ttl > 604800 {
		return errors.New("ttl must be between 300 and 604800 seconds")
	}
	if views < 1 || views > 100 {
		return errors.New("views must be between 1 and 100")
	}
	return nil
}
