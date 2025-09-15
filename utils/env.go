package utils

import (
	"github.com/flosch/pongo2"
	"github.com/labstack/gommon/log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	REDIS_HOST      string
	REDIS_PASSWORD  string
	REDIS_PORT      string
	REDIS_DB        string
	REDIS_PREFIX    string
	TOKEN_SEPARATOR string
	NO_SSL          bool = false
	APP_PORT        string
	LOGO            string
	APP_NAME        string
	DISCLAIMER      string
	COPYRIGHT       string
	FILEFOLDER      string
	ZIP_COMPRESSION string
	ZIP_AUTO_THRESHOLD_MB string
	MAXFILESIZE     string
	MaxFileSize     int64
	DataContext     pongo2.Context
)

func init() {
	if REDIS_HOST = os.Getenv("REDIS_HOST"); REDIS_HOST == "" {
		REDIS_HOST = "localhost"
	}
	if REDIS_PASSWORD = os.Getenv("REDIS_PASSWORD"); REDIS_PASSWORD == "" {
		REDIS_PASSWORD = ""
	}
	if REDIS_PORT = os.Getenv("REDIS_PORT"); REDIS_PORT == "" {
		REDIS_PORT = "6379"
	}
	if REDIS_DB = os.Getenv("REDIS_DB"); REDIS_DB == "" {
		REDIS_DB = "0"
	}
	if REDIS_PREFIX = os.Getenv("REDIS_PREFIX"); REDIS_PREFIX == "" {
		REDIS_PREFIX = "okuru_"
	}
	if TOKEN_SEPARATOR = os.Getenv("OKURU_TOKEN_SEPARATOR"); TOKEN_SEPARATOR == "" {
		TOKEN_SEPARATOR = "~"
	}
	if NoSslEnv := os.Getenv("NO_SSL"); NoSslEnv == "" {
		NO_SSL = false
	}
	if APP_PORT = os.Getenv("OKURU_APP_PORT"); APP_PORT == "" {
		APP_PORT = "4000"
	}
	if LOGO = os.Getenv("OKURU_LOGO"); LOGO == "" {
		LOGO = ""
	}
	if APP_NAME = os.Getenv("OKURU_APP_NAME"); APP_NAME == "" {
		APP_NAME = "送る"
	}
	if DISCLAIMER = os.Getenv("OKURU_DISCLAIMER"); DISCLAIMER == "" {
		DISCLAIMER = `THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\nIMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\nFITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\nAUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\nLIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\nOUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\nSOFTWARE.`
	}
	if COPYRIGHT = os.Getenv("OKURU_COPYRIGHT"); COPYRIGHT == "" {
		COPYRIGHT = ``
	}
	if FILEFOLDER = os.Getenv("OKURU_FILE_FOLDER"); FILEFOLDER == "" {
		FILEFOLDER = "data/"
	}
	if ZIP_COMPRESSION = os.Getenv("OKURU_ZIP_COMPRESSION"); OKURU_ZIP_COMPRESSION == "" {
		OKURU_ZIP_COMPRESSION = "store"
	}
	if ZIP_AUTO_THRESHOLD_MB = os.Getenv("OKURU_ZIP_AUTO_THRESHOLD_MB"); OKURU_ZIP_AUTO_THRESHOLD_MB == "" {
		OKURU_ZIP_AUTO_THRESHOLD_MB = "100"
	}
	if MAXFILESIZE = os.Getenv("OKURU_MAX_FILE_SIZE"); MAXFILESIZE == "" {
		MAXFILESIZE = "1024"
	}

	FILEFOLDER, _ = filepath.Abs(FILEFOLDER)
	var err error
	MaxFileSize, err = strconv.ParseInt(MAXFILESIZE, 10, 64)
	if err != nil {
		MaxFileSize = 1024
	}
	MaxFileSize = MaxFileSize * 1024 * 1024 // bytes to megabytes

	log.Debug("REDIS_HOST : %+v\n", REDIS_HOST)
	println("")
	log.Debug("REDIS_PASSWORD : %+v\n", REDIS_PASSWORD)
	println("")
	log.Debug("REDIS_PORT : %+v\n", REDIS_PORT)
	println("")
	log.Debug("REDIS_DB : %+v\n", REDIS_DB)
	println("")
	log.Debug("REDIS_PREFIX : %+v\n", REDIS_PREFIX)
	println("")
	log.Debug("TOKEN_SEPARATOR : %+v\n", TOKEN_SEPARATOR)
	println("")
	log.Debug("NO_SSL : %+v\n", NO_SSL)
	println("")
	log.Debug("File folder : %+v\n", FILEFOLDER)
	println("")
	log.Debug("APP_PORT : %+v\n", APP_PORT)
	println("")
	log.Debug("COPYRIGHT : %+v\n", COPYRIGHT)
	println("")
	log.Debug("LOGO : %+v\n", LOGO)
	println("")
	log.Debug("DISCLAIMER : %+v\n", DISCLAIMER)
	println("")
	log.Debug("APP_NAME : %+v\n", APP_NAME)
	println("")
	log.Debug("OKURU_ZIP_COMPRESSION : %+v\n", OKURU_ZIP_COMPRESSION)
	println("")
	log.Debug("OKURU_ZIP_AUTO_THRESHOLD_MB : %+v\n", OKURU_ZIP_AUTO_THRESHOLD_MB)

	// Init data context that'll be passed to render to avoid creating it every time for those "global" variable
	DataContext = pongo2.Context{
		"logo":       LOGO,
		"APP_NAME":   APP_NAME,
		"disclaimer": "<p>" + strings.Replace(DISCLAIMER, "\\n", "<br>", -1) + "<p>",
		"copyright":  "<p>" + COPYRIGHT + "<p>",
	}
}
