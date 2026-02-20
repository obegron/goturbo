package main

import (
	"sync/atomic"
	"testing"
)

func TestRecordMavenMetrics(t *testing.T) {
	atomic.StoreUint64(&mavenHits, 0)
	atomic.StoreUint64(&mavenMisses, 0)
	atomic.StoreUint64(&mavenPutSuccess, 0)
	atomic.StoreUint64(&mavenPutErrors, 0)

	recordMavenMetrics("GET", 200)
	recordMavenMetrics("GET", 404)
	recordMavenMetrics("PROPFIND", 207)
	recordMavenMetrics("PUT", 201)
	recordMavenMetrics("PUT", 500)

	if got := atomic.LoadUint64(&mavenHits); got != 2 {
		t.Fatalf("mavenHits = %d, want 2", got)
	}
	if got := atomic.LoadUint64(&mavenMisses); got != 1 {
		t.Fatalf("mavenMisses = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&mavenPutSuccess); got != 1 {
		t.Fatalf("mavenPutSuccess = %d, want 1", got)
	}
	if got := atomic.LoadUint64(&mavenPutErrors); got != 1 {
		t.Fatalf("mavenPutErrors = %d, want 1", got)
	}
}
