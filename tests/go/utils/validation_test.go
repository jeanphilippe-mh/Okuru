package utils

import "testing"

func TestParameterBounds(t *testing.T) {
	for _, c := range []struct {
		ttl, views int
		valid      bool
	}{
		{1, 1, true}, {30, 100, true}, {-1, 1, false}, {0, 1, false},
		{31, 1, false}, {1, 0, false}, {1, -1, false}, {1, 101, false},
	} {
		if (ValidateWebLimits(c.ttl, c.views) == nil) != c.valid {
			t.Errorf("web bounds: %+v", c)
		}
	}
	for _, c := range []struct {
		ttl, views int
		valid      bool
	}{
		{300, 1, true}, {604800, 100, true}, {-1, 1, false}, {299, 1, false},
		{604801, 1, false}, {3600, -1, false}, {3600, 101, false},
	} {
		if (ValidateAPILimits(c.ttl, c.views) == nil) != c.valid {
			t.Errorf("API bounds: %+v", c)
		}
	}
}
