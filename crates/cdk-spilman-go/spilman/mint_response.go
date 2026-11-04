package spilman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"
)

// MintResponseEnvelope reads a complete HTTP response for the Rust callback
// contract. HTTP errors return evidence normally; read/decoding failures return
// errors and cannot authorize a retry. The caller owns closing response.Body.
func MintResponseEnvelope(response *http.Response) (string, error) {
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(body) {
		return "", fmt.Errorf("mint response is not valid UTF-8")
	}
	envelope, err := json.Marshal(struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}{response.StatusCode, string(body)})
	return string(envelope), err
}
