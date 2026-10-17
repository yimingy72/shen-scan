package cloud

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManualModeCannotEnableCloudFromStoredSettings(t *testing.T) {
	c := controller{cfg: config{provider: "manual"}}
	w := httptest.NewRecorder()
	c.adminSettings(w, httptest.NewRequest("PUT", "/api/cloud/aliyun", strings.NewReader(`{}`)))
	if w.Code != 409 {
		t.Fatalf("manual mode allowed cloud reconfiguration: %d", w.Code)
	}
}

func TestCredentialStorageAndRedaction(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	v := accountCredentials{"test-id-123456", "test-secret-abcdefghijkl", "token-value"}
	encrypted, err := sealCredentials(key, v)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(v.Secret)) {
		t.Fatal("stored plaintext secret")
	}
	recovered, err := openCredentials(key, encrypted)
	if err != nil || recovered != v {
		t.Fatalf("credential round trip: %v", err)
	}
	encrypted[len(encrypted)-1] ^= 1
	if _, err = openCredentials(key, encrypted); err == nil {
		t.Fatal("accepted modified ciphertext")
	}
	cfg := config{accessKeyID: v.ID, accessKeySecret: v.Secret, securityToken: v.Token, region: "cn-hangzhou", zone: "cn-hangzhou-h"}
	if err := applyAccountInput(&cfg, accountRequest{AccessKeyID: "another-id"}); err == nil {
		t.Fatal("accepted new ID with old secret")
	}
	if err := applyAccountInput(&cfg, accountRequest{Region: "https://example.com"}); err == nil {
		t.Fatal("accepted invalid region")
	}
	raw, _ := json.Marshal(map[string]any{"error": safeAccountError(errors.New(v.ID+v.Secret+v.Token), cfg).Error(), "masked": maskedKey(v.ID)})
	if bytes.Contains(raw, []byte(v.Secret)) || bytes.Contains(raw, []byte(v.ID)) || bytes.Contains(raw, []byte(v.Token)) {
		t.Fatal("credentials leaked in response")
	}
}
