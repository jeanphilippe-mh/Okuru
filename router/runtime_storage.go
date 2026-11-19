package router

import (
	"net/http"
	"strings"
)

// Only publication, transfer preparation and binary upload methods require
// new archive capacity. POST is also used for downloads and file deletion.
func NeedsArchiveCapacity(r *http.Request) bool {
	path := strings.TrimRight(r.URL.Path, "/")
	switch r.Method {
	case http.MethodPatch:
		return strings.HasPrefix(path, sessionPath+"/")
	case http.MethodPost:
		if path == "/file" || path == directFilePath || path == preparedFilePath || path == sessionPath {
			return true
		}
		return strings.HasPrefix(path, sessionPath+"/") && strings.HasSuffix(path, "/complete")
	default:
		return false
	}
}
