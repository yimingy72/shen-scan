package common

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func SourceRecordHash(raw []byte) string {
	var v interface{}
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	canonical, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
func SourceUnitID(engine, source, id, hash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{engine, source, id, hash}, "\x00")))
	return engine + ":" + hex.EncodeToString(sum[:])
}
