//go:build windows && amd64

package spilman

/*
#cgo LDFLAGS: -L${SRCDIR}/../packaged/lib/windows-amd64 -lcdk_spilman_go -lws2_32 -luserenv -lbcrypt -lntdll
*/
import "C"
