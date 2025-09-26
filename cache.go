package main

import (
	"fmt"
	"sync"
	"time"
)

var (
	responseCache = make(map[string]CacheEntry)
	cacheMutex    sync.RWMutex
	cacheExpiry   = 1 * time.Hour // Cache entries expire after 1 hour
)

func getCacheKey(host, path, cid string) string {
	return fmt.Sprintf("%s|%s|%s", host, path, cid)
}

func getCachedResponse(host, path, cid string) (*CacheEntry, bool) {
	cacheMutex.RLock()
	defer cacheMutex.RUnlock()

	key := getCacheKey(host, path, cid)
	entry, exists := responseCache[key]
	if !exists {
		return nil, false
	}

	if time.Since(entry.Timestamp) > cacheExpiry {
		go func() {
			cacheMutex.Lock()
			delete(responseCache, key)
			cacheMutex.Unlock()
		}()
		return nil, false
	}

	return &entry, true
}

func setCachedResponse(host, path, cid, contentType string, data []byte) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	key := getCacheKey(host, path, cid)
	responseCache[key] = CacheEntry{
		ContentType: contentType,
		Data:        data,
		Timestamp:   time.Now(),
	}
}
