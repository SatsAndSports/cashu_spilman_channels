//go:build darwin && amd64

package spilman

/*
#cgo LDFLAGS: -L${SRCDIR}/../packaged/lib/darwin-amd64 -lcdk_spilman_go -lpthread -ldl -lm -framework Security -framework CoreFoundation
*/
import "C"
