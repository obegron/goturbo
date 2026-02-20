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
	turboHits       uint64
	turboMisses     uint64
	turboPutSuccess uint64
	turboPutErrors  uint64

	mavenHits       uint64
	mavenMisses     uint64
	mavenPutSuccess uint64
	mavenPutErrors  uint64

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

	th := atomic.LoadUint64(&turboHits)
	tm := atomic.LoadUint64(&turboMisses)
	mh := atomic.LoadUint64(&mavenHits)
	mm := atomic.LoadUint64(&mavenMisses)
	h := th + mh
	m := tm + mm
	hitRatio := 0.0
	if h+m > 0 {
		hitRatio = float64(h) / float64(h+m)
	}

	turboHitRatio := 0.0
	if th+tm > 0 {
		turboHitRatio = float64(th) / float64(th+tm)
	}
	mavenHitRatio := 0.0
	if mh+mm > 0 {
		mavenHitRatio = float64(mh) / float64(mh+mm)
	}

	stats := map[string]interface{}{
		"server":          "goTurbo",
		"version":         Version,
		"uptime":          timeSinceStart().String(),
		"security":        !config.NoSecurity,
		"enable_turbo":    !config.DisableTurbo,
		"enable_maven":    !config.DisableMaven,
		"hits":            h,
		"misses":          m,
		"hit_ratio":       hitRatio,
		"put_success":     atomic.LoadUint64(&turboPutSuccess) + atomic.LoadUint64(&mavenPutSuccess),
		"put_errors":      atomic.LoadUint64(&turboPutErrors) + atomic.LoadUint64(&mavenPutErrors),
		"turbo_hits":      th,
		"turbo_misses":    tm,
		"turbo_hit_ratio": turboHitRatio,
		"maven_hits":      mh,
		"maven_misses":    mm,
		"maven_hit_ratio": mavenHitRatio,
		"cached_files":    fileCount,
		"total_bytes":     totalBytes,
		"cache_max_age":   config.CacheMaxAge.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	jsonEncode(w, stats)
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	fileCount, totalBytes := getDiskUsage()
	th := atomic.LoadUint64(&turboHits)
	tm := atomic.LoadUint64(&turboMisses)
	tps := atomic.LoadUint64(&turboPutSuccess)
	tpe := atomic.LoadUint64(&turboPutErrors)

	mh := atomic.LoadUint64(&mavenHits)
	mm := atomic.LoadUint64(&mavenMisses)
	mps := atomic.LoadUint64(&mavenPutSuccess)
	mpe := atomic.LoadUint64(&mavenPutErrors)

	h := th + mh
	m := tm + mm
	ps := tps + mps
	pe := tpe + mpe

	hitRatio := 0.0
	if h+m > 0 {
		hitRatio = float64(h) / float64(h+m)
	}
	turboHitRatio := 0.0
	if th+tm > 0 {
		turboHitRatio = float64(th) / float64(th+tm)
	}
	mavenHitRatio := 0.0
	if mh+mm > 0 {
		mavenHitRatio = float64(mh) / float64(mh+mm)
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

	fmt.Fprintf(w, "# HELP goturbo_turbo_hits_total Total number of Turborepo cache hits\n")
	fmt.Fprintf(w, "# TYPE goturbo_turbo_hits_total counter\n")
	fmt.Fprintf(w, "goturbo_turbo_hits_total %d\n", th)
	fmt.Fprintf(w, "# HELP goturbo_turbo_misses_total Total number of Turborepo cache misses\n")
	fmt.Fprintf(w, "# TYPE goturbo_turbo_misses_total counter\n")
	fmt.Fprintf(w, "goturbo_turbo_misses_total %d\n", tm)
	fmt.Fprintf(w, "# HELP goturbo_turbo_put_success_total Total number of successful Turborepo writes\n")
	fmt.Fprintf(w, "# TYPE goturbo_turbo_put_success_total counter\n")
	fmt.Fprintf(w, "goturbo_turbo_put_success_total %d\n", tps)
	fmt.Fprintf(w, "# HELP goturbo_turbo_put_errors_total Total number of failed Turborepo writes\n")
	fmt.Fprintf(w, "# TYPE goturbo_turbo_put_errors_total counter\n")
	fmt.Fprintf(w, "goturbo_turbo_put_errors_total %d\n", tpe)
	fmt.Fprintf(w, "# HELP goturbo_turbo_hit_ratio Turborepo cache hit ratio\n")
	fmt.Fprintf(w, "# TYPE goturbo_turbo_hit_ratio gauge\n")
	fmt.Fprintf(w, "goturbo_turbo_hit_ratio %f\n", turboHitRatio)

	fmt.Fprintf(w, "# HELP goturbo_maven_hits_total Total number of Maven cache hits\n")
	fmt.Fprintf(w, "# TYPE goturbo_maven_hits_total counter\n")
	fmt.Fprintf(w, "goturbo_maven_hits_total %d\n", mh)
	fmt.Fprintf(w, "# HELP goturbo_maven_misses_total Total number of Maven cache misses\n")
	fmt.Fprintf(w, "# TYPE goturbo_maven_misses_total counter\n")
	fmt.Fprintf(w, "goturbo_maven_misses_total %d\n", mm)
	fmt.Fprintf(w, "# HELP goturbo_maven_put_success_total Total number of successful Maven writes\n")
	fmt.Fprintf(w, "# TYPE goturbo_maven_put_success_total counter\n")
	fmt.Fprintf(w, "goturbo_maven_put_success_total %d\n", mps)
	fmt.Fprintf(w, "# HELP goturbo_maven_put_errors_total Total number of failed Maven writes\n")
	fmt.Fprintf(w, "# TYPE goturbo_maven_put_errors_total counter\n")
	fmt.Fprintf(w, "goturbo_maven_put_errors_total %d\n", mpe)
	fmt.Fprintf(w, "# HELP goturbo_maven_hit_ratio Maven cache hit ratio\n")
	fmt.Fprintf(w, "# TYPE goturbo_maven_hit_ratio gauge\n")
	fmt.Fprintf(w, "goturbo_maven_hit_ratio %f\n", mavenHitRatio)
}

func getDiskUsage() (uint64, uint64) {
	return atomic.LoadUint64(&totalFiles), atomic.LoadUint64(&totalBytes)
}
