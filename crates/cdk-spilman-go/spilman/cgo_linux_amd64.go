//go:build linux && amd64

package spilman

/*
#cgo LDFLAGS: -L${SRCDIR}/../packaged/lib/linux-amd64 -lcdk_spilman_go -lpthread -ldl -lm
*/
import "C"
