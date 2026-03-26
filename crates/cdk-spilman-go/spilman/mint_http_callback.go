package spilman

// This file contains the Go export for the HTTP callback used by MintProofsFromMint.
// It must be in a separate file from the CGO preamble in client.go.

/*
#include <stdlib.h>
*/
import "C"
import (
	"runtime/cgo"
	"unsafe"
)

//export go_mint_http_callback
func go_mint_http_callback(userData unsafe.Pointer, method *C.char, url *C.char, body *C.char, responseOut **C.char) *C.char {
	h := cgo.Handle(userData)
	callHTTP := h.Value().(HTTPCallback)

	goMethod := C.GoString(method)
	goURL := C.GoString(url)
	goBody := C.GoString(body)

	response, err := callHTTP(goMethod, goURL, goBody)
	if err != nil {
		return C.CString(err.Error())
	}

	*responseOut = C.CString(response)
	return nil
}
