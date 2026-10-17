package cloud

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cms"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type accountSettings struct {
	Name       string     `json:"name"`
	AccountID  string     `json:"account_id"`
	Region     string     `json:"region"`
	Zone       string     `json:"zone"`
	VerifiedAt *time.Time `json:"verified_at"`
	Revision   int64      `json:"revision"`
	Encrypted  []byte     `json:"encrypted,omitempty"`
}
type accountCredentials struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
	Token  string `json:"token,omitempty"`
}
type accountRequest struct {
	Name             string `json:"name"`
	AccessKeyID      string `json:"access_key_id"`
	AccessKeySecret  string `json:"access_key_secret"`
	SecurityToken    string `json:"security_token"`
	Region           string `json:"region"`
	Zone             string `json:"zone"`
	ExpectedRevision int64  `json:"expected_revision"`
}

func credentialKey(create bool) ([]byte, error) {
	path := env("SCAN_CREDENTIAL_KEY_FILE", "data/cloud-credentials.key")
	if create {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			key := make([]byte, 32)
			_, err = rand.Read(key)
			if err == nil {
				_, err = f.Write(key)
			}
			if err == nil {
				err = f.Sync()
			}
			closeErr := f.Close()
			if err != nil {
				return nil, err
			}
			if closeErr != nil {
				return nil, closeErr
			}
		} else if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, errors.New("云凭据加密密钥不可用")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("云凭据加密密钥权限必须为 0600")
	}
	key, err := os.ReadFile(path)
	if err != nil || len(key) != 32 {
		return nil, errors.New("云凭据加密密钥无效")
	}
	return key, nil
}
func sealCredentials(key []byte, v accountCredentials) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, raw, []byte("scan-platform/aliyun/v1")), nil
}
func openCredentials(key, encrypted []byte) (accountCredentials, error) {
	var v accountCredentials
	block, err := aes.NewCipher(key)
	if err != nil {
		return v, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return v, err
	}
	if len(encrypted) < gcm.NonceSize() {
		return v, errors.New("云凭据密文无效")
	}
	raw, err := gcm.Open(nil, encrypted[:gcm.NonceSize()], encrypted[gcm.NonceSize():], []byte("scan-platform/aliyun/v1"))
	if err != nil {
		return v, errors.New("云凭据解密失败")
	}
	err = json.Unmarshal(raw, &v)
	return v, err
}
func loadAccount(ctx context.Context, db *pgxpool.Pool, cfg *config) (accountSettings, bool, error) {
	var a accountSettings
	var raw []byte
	err := db.QueryRow(ctx, `SELECT settings FROM cloud_account_settings WHERE provider='aliyun'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, false, nil
	}
	if err != nil {
		return a, false, err
	}
	if err = json.Unmarshal(raw, &a); err != nil {
		return a, false, err
	}
	key, err := credentialKey(false)
	if err != nil {
		return a, false, err
	}
	v, err := openCredentials(key, a.Encrypted)
	if err != nil {
		return a, false, err
	}
	cfg.provider = "aliyun"
	cfg.accessKeyID = v.ID
	cfg.accessKeySecret = v.Secret
	cfg.securityToken = v.Token
	cfg.region = a.Region
	cfg.zone = a.Zone
	// Stored accounts take precedence over environment resources. Their network is
	// restored separately from the settings row saved by one-click setup.
	cfg.imageID = ""
	cfg.vswitchIDs = nil
	cfg.securityGroupID = ""
	cfg.instanceTypes = nil
	return a, true, nil
}
func maskedKey(v string) string {
	if len(v) < 8 {
		return "••••"
	}
	return v[:4] + "••••••••" + v[len(v)-4:]
}
func cloudJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func cloudError(w http.ResponseWriter, status int, err error) {
	cloudJSON(w, status, map[string]string{"error": err.Error()})
}
func safeAccountError(err error, c config) error {
	text := shortError(err)
	for _, v := range []string{c.accessKeySecret, c.accessKeyID, c.securityToken} {
		if v != "" {
			text = strings.ReplaceAll(text, v, "[REDACTED]")
		}
	}
	return errors.New(text)
}
func (c *controller) adminSettings(w http.ResponseWriter, r *http.Request) {
	c.cfgMu.RLock()
	manual := c.cfg.provider == "manual"
	c.cfgMu.RUnlock()
	if manual && r.Method != http.MethodGet {
		cloudError(w, 409, errors.New("当前为手动节点模式；请在部署配置中启用 SCAN_CLOUD_PROVIDER=aliyun 后配置云账号"))
		return
	}
	if r.Method == http.MethodGet {
		if strings.HasSuffix(r.URL.Path, "/instances") {
			c.listCloudInstances(w, r)
			return
		}
		c.cfgMu.RLock()
		cfg, a := c.cfg, c.account
		cfgErr := c.configErr
		c.cfgMu.RUnlock()
		if a.Name == "" {
			a.Name = "阿里云账号"
		}
		a.Region, a.Zone = cfg.region, cfg.zone
		a.Encrypted = nil
		var resource providerSettings
		var raw []byte
		err := c.db.QueryRow(r.Context(), `SELECT settings FROM cloud_provider_settings WHERE provider='aliyun'`).Scan(&raw)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			cloudError(w, 503, errors.New("读取云配置失败"))
			return
		}
		if len(raw) > 0 && json.Unmarshal(raw, &resource) != nil {
			cloudError(w, 500, errors.New("云资源配置无效"))
			return
		}
		resource.Region = cfg.region
		resource.Zone = cfg.zone
		resource.ImageID = cfg.imageID
		resource.VSwitchIDs = cfg.vswitchIDs
		resource.SecurityGroup = cfg.securityGroupID
		resource.InstanceTypes = cfg.instanceTypes
		errorText := ""
		if cfgErr != nil {
			errorText = safeAccountError(cfgErr, cfg).Error()
		}
		cloudJSON(w, 200, map[string]any{"account": a, "has_credentials": cfg.accessKeyID != "" && cfg.accessKeySecret != "", "access_key_masked": maskedKey(cfg.accessKeyID), "resources": resource, "ready": cfgErr == nil && cfg.readyError() == nil, "error": errorText})
		return
	}
	var input accountRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		cloudError(w, 400, errors.New("云账号配置格式不正确"))
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		cloudError(w, 400, errors.New("只允许一个配置对象"))
		return
	}
	// Reconfiguration and network reconciliation share one lock; a new account
	// can never replace a client while an instance creation/release is running.
	c.reconcile.Lock()
	defer c.reconcile.Unlock()
	c.cfgMu.RLock()
	candidate, oldAccount := c.cfg, c.account
	c.cfgMu.RUnlock()
	previous := candidate
	if err := applyAccountInput(&candidate, input); err != nil {
		cloudError(w, 400, err)
		return
	}
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = oldAccount.Name
	}
	if name == "" {
		name = "阿里云账号"
	}
	if len([]rune(name)) > 60 {
		cloudError(w, 400, errors.New("账号名称不能超过 60 字"))
		return
	}
	if r.Method == http.MethodPut && input.ExpectedRevision != oldAccount.Revision {
		cloudError(w, 409, errors.New("账号配置已变更，请刷新后重试"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	accountID, err := verifyAliyun(ctx, candidate)
	if err != nil {
		cloudError(w, 422, safeAccountError(err, candidate))
		return
	}
	now := time.Now().UTC()
	if r.Method == http.MethodPost {
		cloudJSON(w, 200, map[string]any{"verified": true, "account_id": accountID, "verified_at": now, "checks": []string{"账号身份", "ECS 查询", "VPC 查询", "系统事件查询"}})
		return
	}
	if r.Method != http.MethodPut {
		cloudError(w, 405, errors.New("不支持的操作"))
		return
	}
	tx, err := c.db.Begin(ctx)
	if err != nil {
		cloudError(w, 503, errors.New("数据库暂不可用"))
		return
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(0x5343414e)); err != nil {
		cloudError(w, 503, err)
		return
	}
	var enabled bool
	var active int
	err = tx.QueryRow(ctx, `SELECT enabled FROM worker_pool WHERE singleton FOR UPDATE`).Scan(&enabled)
	if err == nil {
		err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM cloud_instances WHERE provider='aliyun' AND NOT release_confirmed)+
 (SELECT count(*) FROM cloud_operations WHERE provider='aliyun' AND operation='create' AND state NOT IN('done','failed','abandoned'))`).Scan(&active)
	}
	if err != nil {
		cloudError(w, 503, errors.New("无法确认 Worker 池状态"))
		return
	}
	if enabled || active > 0 {
		cloudError(w, 409, errors.New("请先停止 Worker 池，等待全部实例释放后再保存云账号或地域配置"))
		return
	}
	changedScope := candidate.region != previous.region || candidate.zone != previous.zone ||
		(oldAccount.AccountID != "" && accountID != oldAccount.AccountID) ||
		(oldAccount.AccountID == "" && candidate.accessKeyID != previous.accessKeyID)
	if changedScope {
		candidate.imageID = ""
		candidate.securityGroupID = ""
		candidate.vswitchIDs = nil
		candidate.instanceTypes = nil
	}
	key, err := credentialKey(true)
	if err != nil {
		cloudError(w, 500, err)
		return
	}
	encrypted, err := sealCredentials(key, accountCredentials{candidate.accessKeyID, candidate.accessKeySecret, candidate.securityToken})
	if err != nil {
		cloudError(w, 500, errors.New("加密云凭据失败"))
		return
	}
	account := accountSettings{Name: name, AccountID: accountID, Region: candidate.region, Zone: candidate.zone, VerifiedAt: &now, Revision: oldAccount.Revision + 1, Encrypted: encrypted}
	raw, _ := json.Marshal(account)
	_, err = tx.Exec(ctx, `INSERT INTO cloud_account_settings(provider,settings) VALUES('aliyun',$1) ON CONFLICT(provider) DO UPDATE SET settings=EXCLUDED.settings,updated_at=now()`, raw)
	if err == nil && changedScope {
		_, err = tx.Exec(ctx, `DELETE FROM cloud_provider_settings WHERE provider='aliyun'`)
	}
	if err == nil && !changedScope {
		// Preserve environment-provided resources on the first save as well.
		resources := providerSettings{Region: candidate.region, AccountID: accountID, Zone: candidate.zone, ImageID: candidate.imageID, SecurityGroup: candidate.securityGroupID, VSwitchIDs: candidate.vswitchIDs, InstanceTypes: candidate.instanceTypes}
		resourceRaw, _ := json.Marshal(resources)
		_, err = tx.Exec(ctx, `INSERT INTO cloud_provider_settings(provider,settings) VALUES('aliyun',$1) ON CONFLICT(provider) DO NOTHING`, resourceRaw)
	}
	configurationErr := candidate.validate()
	ready := configurationErr == nil && candidate.readyError() == nil
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE worker_pool SET provider='aliyun',configured=$1,generation=generation+1,error='',updated_at=now() WHERE singleton`, ready)
	}
	if err != nil {
		cloudError(w, 500, errors.New("保存云账号失败"))
		return
	}
	ec, cm, vp, err := newAliyunClients(candidate)
	if err != nil {
		cloudError(w, 500, safeAccountError(err, candidate))
		return
	}
	if err = tx.Commit(ctx); err != nil {
		cloudError(w, 503, errors.New("保存云账号失败"))
		return
	}
	c.cfgMu.Lock()
	c.cfg, c.account, c.configErr = candidate, account, configurationErr
	c.ecs, c.cms, c.vpc = ec, cm, vp
	c.cfgMu.Unlock()
	c.server.SetPoolProvider("aliyun", c.configured, c.Reconcile)
	account.Encrypted = nil
	cloudJSON(w, 200, map[string]any{"saved": true, "account": account, "ready": ready, "network_reset": changedScope})
}

var regionPattern = regexp.MustCompile(`^[a-z]{2}-[a-z0-9-]{2,40}$`)

func applyAccountInput(c *config, in accountRequest) error {
	c.provider = "aliyun"
	if in.Region != "" {
		c.region = strings.TrimSpace(in.Region)
	}
	if in.Zone != "" {
		c.zone = strings.TrimSpace(in.Zone)
	}
	if !regionPattern.MatchString(c.region) || !strings.HasPrefix(c.zone, c.region+"-") || len(c.zone) > 60 {
		return errors.New("地域或可用区格式不正确")
	}
	id, secret := strings.TrimSpace(in.AccessKeyID), strings.TrimSpace(in.AccessKeySecret)
	if id != "" && id != c.accessKeyID && secret == "" {
		return errors.New("更换 AccessKey ID 时必须同时填写 Secret")
	}
	if id != "" {
		c.accessKeyID = id
	}
	if secret != "" {
		c.accessKeySecret = secret
		c.securityToken = strings.TrimSpace(in.SecurityToken)
	}
	if strings.TrimSpace(in.SecurityToken) != "" {
		c.securityToken = strings.TrimSpace(in.SecurityToken)
	}
	if c.accessKeyID == "" || c.accessKeySecret == "" {
		return errors.New("请填写 AccessKey ID 和 Secret")
	}
	for _, value := range []string{c.accessKeyID, c.accessKeySecret, c.securityToken} {
		if len(value) > 8192 || strings.ContainsAny(value, "\r\n\x00") {
			return errors.New("凭据格式不正确")
		}
	}
	return nil
}

func verifyAliyun(ctx context.Context, c config) (string, error) {
	ec, cm, vp, err := newAliyunClients(c)
	if err != nil {
		return "", err
	}
	var client *sts.Client
	if c.securityToken == "" {
		client, err = sts.NewClientWithAccessKey(c.region, c.accessKeyID, c.accessKeySecret)
	} else {
		client, err = sts.NewClientWithStsToken(c.region, c.accessKeyID, c.accessKeySecret, c.securityToken)
	}
	if err != nil {
		return "", err
	}
	client.GetConfig().WithScheme("HTTPS")
	client.SetConnectTimeout(5 * time.Second)
	client.SetReadTimeout(12 * time.Second)
	identity, err := client.GetCallerIdentity(sts.CreateGetCallerIdentityRequest())
	if err != nil {
		return "", fmt.Errorf("账号身份验证失败：%w", err)
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	ec.SetReadTimeout(12 * time.Second)
	vp.SetReadTimeout(12 * time.Second)
	cm.SetReadTimeout(12 * time.Second)
	zones, err := ec.DescribeZones(ecs.CreateDescribeZonesRequest())
	if err != nil {
		return "", fmt.Errorf("ECS 查询失败：%w", err)
	}
	found := false
	for _, z := range zones.Zones.Zone {
		if z.ZoneId == c.zone {
			found = true
		}
	}
	if !found {
		return "", errors.New("该地域中没有指定的可用区")
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	vpcRequest := vpc.CreateDescribeVpcsRequest()
	vpcRequest.PageSize = requests.NewInteger(1)
	if _, err = vp.DescribeVpcs(vpcRequest); err != nil {
		return "", fmt.Errorf("VPC 查询失败：%w", err)
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	eventRequest := cms.CreateDescribeSystemEventAttributeRequest()
	eventRequest.Product = "ECS"
	eventRequest.Name = "Instance:PreemptibleInstanceInterruption"
	eventRequest.PageSize = requests.NewInteger(1)
	if _, err = cm.DescribeSystemEventAttribute(eventRequest); err != nil {
		return "", fmt.Errorf("系统事件查询失败：%w", err)
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	return identity.AccountId, nil
}

func (c *controller) listCloudInstances(w http.ResponseWriter, r *http.Request) {
	c.cfgMu.RLock()
	poolID := c.cfg.poolID
	c.cfgMu.RUnlock()
	rows, err := c.db.Query(r.Context(), `SELECT jsonb_build_object('instance_id',instance_id,'state',state,'released',release_confirmed,
 'drain_started',drain_started,'created_at',created_at,'updated_at',updated_at,'details',details)
 FROM cloud_instances WHERE provider='aliyun' AND pool_id=$1 ORDER BY release_confirmed,created_at DESC LIMIT 1000`, poolID)
	if err != nil {
		cloudError(w, 503, errors.New("读取云节点失败"))
		return
	}
	defer rows.Close()
	items := make([]json.RawMessage, 0)
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			cloudError(w, 500, errors.New("读取云节点失败"))
			return
		}
		items = append(items, raw)
	}
	if err = rows.Err(); err != nil {
		cloudError(w, 503, errors.New("读取云节点失败"))
		return
	}
	cloudJSON(w, 200, map[string]any{"items": items})
}
