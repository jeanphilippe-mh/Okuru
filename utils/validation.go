package utils

import "errors"

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
