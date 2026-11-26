package utils

import (
	"net/http"
	"sync"
)

// RequestCapacity keeps a bounded count of active operations. Optional
// resource keys must be canonical identifiers, never bearer credentials.
type RequestCapacity struct {
	mu                           sync.Mutex
	total, maxTotal              int
	perClient, perResource       map[string]int
	maxPerClient, maxPerResource int
}

func NewRequestCapacity(total, perClient, perResource int) *RequestCapacity {
	return &RequestCapacity{
		maxTotal: total, maxPerClient: perClient, maxPerResource: perResource,
		perClient: make(map[string]int), perResource: make(map[string]int),
	}
}

// TryAcquire returns a release function to call once, or nil at capacity.
// Shared proxies and unavailable identities remain subject to the global
// budget and any resource budget, with no fabricated per-visitor identity.
func (b *RequestCapacity) TryAcquire(r *http.Request, resource string) func() {
	var client string
	if b.maxPerClient > 0 {
		address, _, forwarded, trustedPeer, err := resolveClientAddress(r)
		if err == nil && (!trustedPeer || forwarded) {
			if identity := clientAddressBucket(address); !SharedClientIdentity(identity) {
				client = identity
			}
		}
	}
	if b.maxPerResource <= 0 {
		resource = ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.total >= b.maxTotal ||
		(client != "" && b.perClient[client] >= b.maxPerClient) ||
		(resource != "" && b.perResource[resource] >= b.maxPerResource) {
		return nil
	}
	b.total++
	if client != "" {
		b.perClient[client]++
	}
	if resource != "" {
		b.perResource[resource]++
	}
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.total--
		releaseRequestCapacity(b.perClient, client)
		releaseRequestCapacity(b.perResource, resource)
	}
}

func releaseRequestCapacity(active map[string]int, key string) {
	if key == "" {
		return
	}
	if active[key] == 1 {
		delete(active, key)
		return
	}
	active[key]--
}
