package utils

import (
	"bytes"
	"context"
	"crypto/md5"  // #nosec G501 -- DB-IP publishes MD5 for corruption detection, not authentication.
	"crypto/sha1" // #nosec G505 -- DB-IP publishes SHA-1 for corruption detection, not authentication.
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/html"
)

const (
	geoIPChecksumsSource       = "https://db-ip.com/db/download/ip-to-country-lite"
	maxGeoIPChecksumsPageBytes = 1 << 20
)

type geoIPChecksums struct {
	md5  [md5.Size]byte
	sha1 [sha1.Size]byte
}

// fetchGeoIPChecksums accepts only the fixed DB-IP page through the same
// restricted HTTPS client as the database. The page is not a signed manifest.
func (u *geoIPAutoUpdater) fetchGeoIPChecksums(ctx context.Context, expectedURL string) (geoIPChecksums, error) {
	var empty geoIPChecksums
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, geoIPChecksumsSource, nil)
	if err != nil {
		return empty, errGeoIPUpdateChecksum
	}
	req.Header.Set("User-Agent", "Okuru-GeoIP-Update/1.0")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := u.client.Do(req)
	if err != nil {
		return empty, errGeoIPUpdateChecksum
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxGeoIPChecksumsPageBytes {
		return empty, errGeoIPUpdateChecksum
	}
	page, err := io.ReadAll(io.LimitReader(resp.Body, maxGeoIPChecksumsPageBytes+1))
	if err != nil || len(page) > maxGeoIPChecksumsPageBytes {
		return empty, errGeoIPUpdateChecksum
	}
	return parseGeoIPChecksums(page, expectedURL)
}

func parseGeoIPChecksums(page []byte, expectedURL string) (geoIPChecksums, error) {
	var result geoIPChecksums
	if !strings.HasPrefix(expectedURL, geoIPUpdateSource) || !strings.HasSuffix(expectedURL, ".mmdb.gz") {
		return result, errGeoIPUpdateChecksum
	}
	monthName := strings.TrimSuffix(strings.TrimPrefix(expectedURL, geoIPUpdateSource), ".mmdb.gz")
	month, err := time.Parse("2006-01", monthName)
	if err != nil || month.Format("2006-01") != monthName {
		return result, errGeoIPUpdateChecksum
	}
	doc, err := html.Parse(bytes.NewReader(page))
	if err != nil {
		return result, errGeoIPUpdateChecksum
	}
	// Bound subsequent tree walks even when a hostile response is deeply nested.
	type pendingNode struct {
		node  *html.Node
		depth int
	}
	pending := []pendingNode{{doc, 0}}
	nodes, cards := 0, 0
	for len(pending) != 0 {
		item := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		nodes++
		if nodes > 20000 || item.depth > 128 {
			return result, errGeoIPUpdateChecksum
		}
		if item.node.Type == html.ElementNode && item.node.Data == "div" && geoIPHasClass(item.node, "card") {
			cards++
			if cards > 128 {
				return result, errGeoIPUpdateChecksum
			}
		}
		for c := item.node.FirstChild; c != nil; c = c.NextSibling {
			pending = append(pending, pendingNode{c, item.depth + 1})
		}
	}
	var matchingCards []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "div" && geoIPHasClass(n, "card") && geoIPCountURL(n, expectedURL) > 0 {
			matchingCards = append(matchingCards, n)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(doc)
	if len(matchingCards) != 1 || geoIPCountURL(matchingCards[0], expectedURL) != 1 {
		return result, errGeoIPUpdateChecksum
	}
	values := make(map[string][]string)
	var collect func(*html.Node)
	collect = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "dt" {
			label := strings.TrimSpace(geoIPHTMLText(n))
			if label == "Format" || label == "Release" || label == "MD5SUM" || label == "SHA1SUM" {
				next := n.NextSibling
				for next != nil && next.Type == html.TextNode && strings.TrimSpace(next.Data) == "" {
					next = next.NextSibling
				}
				if next == nil || next.Type != html.ElementNode || next.Data != "dd" {
					values[label] = append(values[label], "")
				} else {
					values[label] = append(values[label], strings.TrimSpace(geoIPHTMLText(next)))
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			collect(child)
		}
	}
	collect(matchingCards[0])
	if len(values["Format"]) != 1 || values["Format"][0] != "MMDB" || len(values["Release"]) != 1 || values["Release"][0] != month.Format("January 2006") || len(values["MD5SUM"]) != 1 || len(values["SHA1SUM"]) != 1 {
		return result, errGeoIPUpdateChecksum
	}
	m, err1 := hex.DecodeString(values["MD5SUM"][0])
	s, err2 := hex.DecodeString(values["SHA1SUM"][0])
	if err1 != nil || err2 != nil || len(m) != len(result.md5) || len(s) != len(result.sha1) {
		return result, errGeoIPUpdateChecksum
	}
	copy(result.md5[:], m)
	copy(result.sha1[:], s)
	return result, nil
}

func geoIPHasClass(n *html.Node, class string) bool {
	for _, a := range n.Attr {
		if a.Key == "class" {
			for _, c := range strings.Fields(a.Val) {
				if c == class {
					return true
				}
			}
		}
	}
	return false
}

func geoIPCountURL(n *html.Node, expectedURL string) int {
	count := 0
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, a := range n.Attr {
			if a.Key == "href" && a.Val == expectedURL {
				count++
			}
		}
	}
	for child := n.FirstChild; child != nil; child = child.NextSibling {
		count += geoIPCountURL(child, expectedURL)
	}
	return count
}

func geoIPHTMLText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(x *html.Node) {
		if x.Type == html.TextNode {
			b.WriteString(x.Data)
		}
		for child := x.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return b.String()
}

// MD5 and SHA-1 are used only to compare against the publisher's own
// checksums. Neither is a signature or an authentication mechanism.
func verifyGeoIPChecksums(data []byte, expected geoIPChecksums) bool {
	m := md5.Sum(data)  // #nosec G401 -- compatibility with the publisher checksum
	s := sha1.Sum(data) // #nosec G401 -- compatibility with the publisher checksum
	return subtle.ConstantTimeCompare(m[:], expected.md5[:]) == 1 && subtle.ConstantTimeCompare(s[:], expected.sha1[:]) == 1
}
