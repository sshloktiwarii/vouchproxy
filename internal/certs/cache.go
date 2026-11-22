package certs

import (
	"crypto/tls"
	"sync"
	"time"
)

type cachedCert struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

// CertCache provides thread-safe LRU caching for dynamically generated leaf certificates.
type CertCache struct {
	mu      sync.RWMutex
	maxSize int
	entries map[string]*cachedCert
	order   []string
}

// NewCertCache creates a new certificate cache with the specified capacity.
func NewCertCache(maxSize int) *CertCache {
	if maxSize <= 0 {
		maxSize = 500
	}
	return &CertCache{
		maxSize: maxSize,
		entries: make(map[string]*cachedCert),
		order:   make([]string, 0, maxSize),
	}
}

// Get retrieves a valid cached certificate for the host if present and not expiring soon.
func (c *CertCache) Get(host string) (*tls.Certificate, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, ok := c.entries[host]
	if !ok {
		return nil, false
	}

	// Invalidate if expiring within 12 hours
	if time.Now().After(item.expiresAt.Add(-12 * time.Hour)) {
		return nil, false
	}

	return item.cert, true
}

// Set inserts or updates a certificate in the cache.
func (c *CertCache) Set(host string, cert *tls.Certificate, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.entries[host]; exists {
		c.entries[host] = &cachedCert{cert: cert, expiresAt: expiresAt}
		return
	}

	if len(c.order) >= c.maxSize {
		// Evict oldest entry
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}

	c.order = append(c.order, host)
	c.entries[host] = &cachedCert{cert: cert, expiresAt: expiresAt}
}
