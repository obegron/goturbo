package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
)

// Metrics
var (
	hits       uint64
	misses     uint64
	putSuccess uint64
	putErrors  uint64
	totalFiles uint64
	totalBytes uint64
)

func InitCacheMetrics() {
	log.Printf("Initializing cache metrics from %s...", config.CacheDir)
	var count uint64
	var size uint64
	filepath.WalkDir(config.CacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		count++
		size += uint64(info.Size())
		return nil
	})
	atomic.StoreUint64(&totalFiles, count)
	atomic.StoreUint64(&totalBytes, size)
	log.Printf("Cache initialized: %d files, %d bytes", count, size)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	fileCount, totalBytes := getDiskUsage()

	h := atomic.LoadUint64(&hits)
	m := atomic.LoadUint64(&misses)
	hitRatio := 0.0
	if h+m > 0 {
		hitRatio = float64(h) / float64(h+m)
	}

	stats := map[string]interface{}{
		"server":        "goTurbo",
		"version":       Version,
		"uptime":        timeSinceStart().String(),
		"security":      !config.NoSecurity,
		"hits":          h,
		"misses":        m,
		"hit_ratio":     hitRatio,
		"put_success":   atomic.LoadUint64(&putSuccess),
		"put_errors":    atomic.LoadUint64(&putErrors),
		"cached_files":  fileCount,
		"total_bytes":   totalBytes,
		"cache_max_age": config.CacheMaxAge.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	jsonEncode(w, stats)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	fileCount, totalBytes := getDiskUsage()
	h := atomic.LoadUint64(&hits)
	m := atomic.LoadUint64(&misses)
	ps := atomic.LoadUint64(&putSuccess)
	pe := atomic.LoadUint64(&putErrors)

	hitRatio := 0.0
	if h+m > 0 {
		hitRatio = float64(h) / float64(h+m)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP goturbo_hits_total Total number of cache hits\n")
	fmt.Fprintf(w, "# TYPE goturbo_hits_total counter\n")
	fmt.Fprintf(w, "goturbo_hits_total %d\n", h)

	fmt.Fprintf(w, "# HELP goturbo_misses_total Total number of cache misses\n")
	fmt.Fprintf(w, "# TYPE goturbo_misses_total counter\n")
	fmt.Fprintf(w, "goturbo_misses_total %d\n", m)

	fmt.Fprintf(w, "# HELP goturbo_put_success_total Total number of successful puts\n")
	fmt.Fprintf(w, "# TYPE goturbo_put_success_total counter\n")
	fmt.Fprintf(w, "goturbo_put_success_total %d\n", ps)

	fmt.Fprintf(w, "# HELP goturbo_put_errors_total Total number of failed puts\n")
	fmt.Fprintf(w, "# TYPE goturbo_put_errors_total counter\n")
	fmt.Fprintf(w, "goturbo_put_errors_total %d\n", pe)

	fmt.Fprintf(w, "# HELP goturbo_cached_files_count Current number of files in cache\n")
	fmt.Fprintf(w, "# TYPE goturbo_cached_files_count gauge\n")
	fmt.Fprintf(w, "goturbo_cached_files_count %d\n", fileCount)

	fmt.Fprintf(w, "# HELP goturbo_cache_size_bytes Total size of cache in bytes\n")
	fmt.Fprintf(w, "# TYPE goturbo_cache_size_bytes gauge\n")
	fmt.Fprintf(w, "goturbo_cache_size_bytes %d\n", totalBytes)

	fmt.Fprintf(w, "# HELP goturbo_cache_hit_ratio Cache hit ratio\n")
	fmt.Fprintf(w, "# TYPE goturbo_cache_hit_ratio gauge\n")
	fmt.Fprintf(w, "goturbo_cache_hit_ratio %f\n", hitRatio)
}

func getDiskUsage() (uint64, uint64) {
	return atomic.LoadUint64(&totalFiles), atomic.LoadUint64(&totalBytes)
}
