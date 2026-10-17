package control

import (
	"bytes"
	"encoding/json"
)

// JSONB cannot store NUL. Keep a readable index and, only when necessary,
// the original JSON in BYTEA so observation details remain lossless.
func observationStorageJSON(raw []byte) (index, original []byte, err error) {
	if !bytes.Contains(raw, []byte(`\u0000`)) {
		return raw, nil, nil
	}
	index, changed, err := catalogIndexJSON(json.RawMessage(raw))
	if err != nil {
		return nil, nil, err
	}
	if len(changed) == 0 { // A literal backslash-u0000 is valid JSONB text.
		return raw, nil, nil
	}
	return index, raw, nil
}
