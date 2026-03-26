//go:build darwin && arm64

package spilman

/*
#cgo LDFLAGS: -L${SRCDIR}/../packaged/lib/darwin-arm64 -lcdk_spilman_go -lpthread -ldl -lm -framework Security -framework CoreFoundation
*/
import "C"
