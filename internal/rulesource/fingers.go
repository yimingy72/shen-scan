package rulesource

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"scanplatform/internal/fingerprintbundle"
)

const (
	FingersID             = "fingers"
	maxFingersAPIResponse = 12 << 20
)

var fingersSource = Source{ID: FingersID, Name: "fingers passive fingerprints", Repository: fingerprintbundle.Repository, Owner: "chainreactors", Repo: "fingers"}

// FingersNotice retains attribution without applying the repository code license
// to independently sourced fingerprint databases.
const FingersNotice = `The four resources are committed data distributed by chainreactors/fingers. Native fingers and aliases: https://github.com/chainreactors/fingers . FingerprintHub-derived data: https://github.com/0x727/FingerprintHub . EHole-derived data: https://github.com/EdgeSecurityTeam/EHole . Each file retains its exact upstream bytes and commit URL. These databases have distinct upstream provenance; no blanket MIT license or independent relicensing is asserted. Consult the corresponding upstream project and original notices before redistribution.`

// FetchFingersRevision downloads only the four fixed data resources from one
// immutable Git commit. It never downloads or executes upstream source code.
func FetchFingersRevision(ctx context.Context, revision string) (fingerprintbundle.RawInput, error) {
	return fetchFingersRevision(ctx, revision, sourceHTTPClient("api.github.com"))
}

func fetchFingersRevision(ctx context.Context, revision string, client *http.Client) (fingerprintbundle.RawInput, error) {
	input := fingerprintbundle.RawInput{SourceRevision: revision, Files: make(map[string][]byte)}
	if !validCommitSHA(revision) || revision != strings.ToLower(revision) {
		return input, fmt.Errorf("fingers revision must be a full lowercase commit SHA")
	}
	var expanded int
	for _, filePath := range fingerprintbundle.Paths() {
		url := "https://api.github.com/repos/chainreactors/fingers/contents/" + filePath + "?ref=" + revision
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return input, err
		}
		req.Header.Set("User-Agent", "scanplatform-fingerprint-source/1")
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := client.Do(req)
		if err != nil {
			return input, fmt.Errorf("download %s: %w", filePath, err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, maxFingersAPIResponse+1))
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return input, fmt.Errorf("download %s: upstream returned %s", filePath, response.Status)
		}
		if readErr != nil {
			return input, fmt.Errorf("download %s: %w", filePath, readErr)
		}
		if len(payload) > maxFingersAPIResponse {
			return input, fmt.Errorf("download %s: GitHub API response exceeds byte limit", filePath)
		}
		data, err := decodeFingersContents(filePath, payload)
		if err != nil {
			return input, err
		}
		decoded, err := fingerprintbundle.DecodeRaw(filePath, data)
		if err != nil {
			return input, err
		}
		expanded += len(decoded)
		if expanded > fingerprintbundle.MaxDecodedTotalBytes {
			return input, fmt.Errorf("fingers resources exceed decoded total limit")
		}
		input.Files[filePath] = data
	}
	return input, nil
}

func decodeFingersContents(filePath string, payload []byte) ([]byte, error) {
	var file struct {
		Type     string `json:"type"`
		Path     string `json:"path"`
		Encoding string `json:"encoding"`
		Size     int64  `json:"size"`
		SHA      string `json:"sha"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(payload, &file); err != nil {
		return nil, fmt.Errorf("download %s: invalid GitHub contents response: %w", filePath, err)
	}
	if file.Type != "file" || file.Path != filePath || file.Encoding != "base64" || file.Size <= 0 || file.Size > fingerprintbundle.MaxRawFileBytes || !validCommitSHA(file.SHA) || file.SHA != strings.ToLower(file.SHA) {
		return nil, fmt.Errorf("download %s: invalid GitHub contents identity, encoding or size", filePath)
	}
	content := strings.NewReplacer("\r", "", "\n", "").Replace(file.Content)
	if len(content) > base64.StdEncoding.EncodedLen(fingerprintbundle.MaxRawFileBytes) {
		return nil, fmt.Errorf("download %s: encoded resource exceeds byte limit", filePath)
	}
	data, err := base64.StdEncoding.Strict().DecodeString(content)
	if err != nil || int64(len(data)) != file.Size {
		return nil, fmt.Errorf("download %s: invalid base64 content or size mismatch", filePath)
	}
	// Git SHA-1 identifies the committed blob; it is not the package digest.
	hash := sha1.New()
	fmt.Fprintf(hash, "blob %d\x00", len(data))
	hash.Write(data)
	if hex.EncodeToString(hash.Sum(nil)) != file.SHA {
		return nil, fmt.Errorf("download %s: Git blob identity mismatch", filePath)
	}
	return data, nil
}
