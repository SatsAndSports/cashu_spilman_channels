//go:build spilman_dev

// This file is used for development builds when the packaged libraries don't exist yet.
// Build with: go build -tags spilman_dev
// The LD_LIBRARY_PATH must include the target/debug directory at runtime.

package spilman

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../target/debug -lcdk_spilman_go -lpthread -ldl -lm
*/
import "C"
