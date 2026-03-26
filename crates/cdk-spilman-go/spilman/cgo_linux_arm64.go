//go:build linux && arm64

package spilman

/*
#cgo LDFLAGS: -L${SRCDIR}/../packaged/lib/linux-arm64 -lcdk_spilman_go -lpthread -ldl -lm
*/
import "C"
