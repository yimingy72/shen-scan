package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	sdkerrors "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type providerSettings struct {
	Region        string   `json:"region"`
	AccountID     string   `json:"account_id"`
	VPCID         string   `json:"vpc_id"`
	VSwitchIDs    []string `json:"vswitch_ids"`
	SecurityGroup string   `json:"security_group_id"`
	ImageID       string   `json:"image_id"`
	InstanceTypes []string `json:"instance_types"`
	Zone          string   `json:"zone"`
	VSwitchCIDR   string   `json:"vswitch_cidr"`
	VPCCIDR       string   `json:"vpc_cidr"`
}

func loadStoredSettings(ctx context.Context, db *pgxpool.Pool, cfg *config) error {
	var raw []byte
	err := db.QueryRow(ctx, `SELECT settings FROM cloud_provider_settings WHERE provider='aliyun'`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved providerSettings
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	if saved.Region != "" && saved.Region != cfg.region {
		return nil
	}
	if cfg.imageID == "" {
		cfg.imageID = saved.ImageID
	}
	if cfg.securityGroupID == "" {
		cfg.securityGroupID = saved.SecurityGroup
	}
	if len(cfg.vswitchIDs) == 0 {
		cfg.vswitchIDs = saved.VSwitchIDs
	}
	if len(cfg.instanceTypes) == 0 {
		cfg.instanceTypes = saved.InstanceTypes
	}
	return nil
}

// Setup creates or discovers the dedicated network and selects worker resources.
// It is called only by the authenticated control-plane setup endpoint.
func (c *controller) Setup(ctx context.Context) (map[string]any, error) {
	c.reconcile.Lock()
	defer c.reconcile.Unlock()
	if c.cfg.provider != "aliyun" {
		return nil, errors.New("cloud setup requires SCAN_CLOUD_PROVIDER=aliyun")
	}
	if c.configErr != nil {
		return nil, c.configErr
	}
	pool, err := c.loadPool(ctx)
	if err != nil {
		return nil, err
	}
	if pool.Enabled {
		return nil, errors.New("请先停止 Worker 池，再调整云资源")
	}

	vpcID, err := c.ensureVPC(ctx)
	if err != nil {
		return nil, fmt.Errorf("setup VPC: %s", shortError(err))
	}
	if err := c.waitVPC(ctx, vpcID); err != nil {
		return nil, errors.New(shortError(err))
	}
	vswitchID, err := c.ensureVSwitch(ctx, vpcID)
	if err != nil {
		return nil, fmt.Errorf("setup vSwitch: %s", shortError(err))
	}
	securityGroup, err := c.ensureSecurityGroup(ctx, vpcID)
	if err != nil {
		return nil, fmt.Errorf("setup security group: %s", shortError(err))
	}
	instanceTypes, err := c.discoverInstanceTypes(ctx)
	if err != nil {
		return nil, fmt.Errorf("discover compatible instance types: %s", shortError(err))
	}
	imageID, err := c.discoverUbuntuImage(ctx, instanceTypes[0])
	if err != nil {
		return nil, fmt.Errorf("discover Ubuntu 22.04 image: %s", shortError(err))
	}
	settings := providerSettings{
		Region: c.cfg.region, AccountID: c.account.AccountID,
		VPCID: vpcID, VSwitchIDs: []string{vswitchID}, SecurityGroup: securityGroup,
		ImageID: imageID, InstanceTypes: instanceTypes, Zone: c.cfg.zone,
		VPCCIDR: "10.77.0.0/16", VSwitchCIDR: "10.77.1.0/24",
	}
	raw, _ := json.Marshal(settings)
	if _, err := c.db.Exec(ctx, `INSERT INTO cloud_provider_settings(provider,settings) VALUES('aliyun',$1)
		ON CONFLICT(provider) DO UPDATE SET settings=EXCLUDED.settings,updated_at=now()`, raw); err != nil {
		return nil, fmt.Errorf("save cloud settings: %w", err)
	}
	c.cfgMu.Lock()
	c.cfg.vswitchIDs = settings.VSwitchIDs
	c.cfg.securityGroupID = securityGroup
	c.cfg.instanceTypes = instanceTypes
	c.cfg.imageID = imageID
	c.cfgMu.Unlock()
	pool, _ = c.loadPool(ctx)
	_ = c.server.UpdatePoolRuntime(ctx, "aliyun", true, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, "")
	return map[string]any{
		"provider": "aliyun", "region": c.cfg.region, "zone": c.cfg.zone,
		"vpc_id": vpcID, "vswitch_id": vswitchID, "security_group_id": securityGroup,
		"image_id": imageID, "instance_types": instanceTypes,
	}, nil
}

func (c *controller) ensureVPC(ctx context.Context) (string, error) {
	request := vpc.CreateDescribeVpcsRequest()
	request.PageSize = requests.NewInteger(50)
	request.Tag = &[]vpc.DescribeVpcsTag{{Key: poolTag, Value: c.cfg.poolID}}
	response, err := c.vpc.DescribeVpcs(request)
	if err != nil {
		return "", err
	}
	for _, item := range response.Vpcs.Vpc {
		if vpcTagValue(item.Tags.Tag, poolTag) == c.cfg.poolID {
			if item.CidrBlock != "10.77.0.0/16" {
				return "", fmt.Errorf("managed VPC %s has unexpected CIDR %s", item.VpcId, item.CidrBlock)
			}
			return item.VpcId, nil
		}
	}
	key := operationKey(c.cfg.poolID+":"+c.cfg.region, "setup-vpc", 0, 0)
	details := map[string]any{"cidr": "10.77.0.0/16", "region": c.cfg.region}
	if err := c.beginSetupOperation(ctx, key, "setup-vpc", details); err != nil {
		return "", err
	}
	create := vpc.CreateCreateVpcRequest()
	create.ClientToken = key
	create.VpcName = "scan-platform"
	create.Description = "Dedicated network for scan-platform workers"
	create.CidrBlock = "10.77.0.0/16"
	create.Tag = &[]vpc.CreateVpcTag{{Key: poolTag, Value: c.cfg.poolID}, {Key: operationTag, Value: key}}
	created, err := c.vpc.CreateVpc(create)
	if err != nil {
		c.finishSetupOperation(ctx, key, err, nil)
		return "", err
	}
	c.finishSetupOperation(ctx, key, nil, map[string]any{"vpc_id": created.VpcId, "request_id": created.RequestId})
	return created.VpcId, nil
}

func (c *controller) waitVPC(ctx context.Context, id string) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		request := vpc.CreateDescribeVpcsRequest()
		request.VpcId = id
		response, err := c.vpc.DescribeVpcs(request)
		if err != nil {
			return fmt.Errorf("wait VPC %s: %w", id, err)
		}
		if len(response.Vpcs.Vpc) == 1 && strings.EqualFold(response.Vpcs.Vpc[0].Status, "Available") {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait VPC %s: %w", id, ctx.Err())
		case <-ticker.C:
		}
	}
}

func (c *controller) ensureVSwitch(ctx context.Context, vpcID string) (string, error) {
	request := vpc.CreateDescribeVSwitchesRequest()
	request.VpcId = vpcID
	request.ZoneId = c.cfg.zone
	request.PageSize = requests.NewInteger(50)
	request.Tag = &[]vpc.DescribeVSwitchesTag{{Key: poolTag, Value: c.cfg.poolID}}
	response, err := c.vpc.DescribeVSwitches(request)
	if err != nil {
		return "", err
	}
	for _, item := range response.VSwitches.VSwitch {
		if vpcTagValue(item.Tags.Tag, poolTag) == c.cfg.poolID {
			if item.CidrBlock != "10.77.1.0/24" || item.ZoneId != c.cfg.zone {
				return "", fmt.Errorf("managed vSwitch %s has unexpected zone or CIDR", item.VSwitchId)
			}
			return item.VSwitchId, nil
		}
	}
	key := operationKey(c.cfg.poolID+":"+c.cfg.region+":"+c.cfg.zone, "setup-vswitch", 0, 0)
	details := map[string]any{"vpc_id": vpcID, "zone": c.cfg.zone, "cidr": "10.77.1.0/24"}
	if err := c.beginSetupOperation(ctx, key, "setup-vswitch", details); err != nil {
		return "", err
	}
	create := vpc.CreateCreateVSwitchRequest()
	create.ClientToken = key
	create.VpcId = vpcID
	create.ZoneId = c.cfg.zone
	create.CidrBlock = "10.77.1.0/24"
	create.VSwitchName = "scan-platform-workers"
	create.Description = "Dedicated subnet for scan-platform workers"
	create.Tag = &[]vpc.CreateVSwitchTag{{Key: poolTag, Value: c.cfg.poolID}, {Key: operationTag, Value: key}}
	created, err := c.vpc.CreateVSwitch(create)
	if err != nil {
		c.finishSetupOperation(ctx, key, err, nil)
		return "", err
	}
	c.finishSetupOperation(ctx, key, nil, map[string]any{"vswitch_id": created.VSwitchId, "request_id": created.RequestId})
	return created.VSwitchId, nil
}

func (c *controller) ensureSecurityGroup(ctx context.Context, vpcID string) (string, error) {
	request := ecs.CreateDescribeSecurityGroupsRequest()
	request.VpcId = vpcID
	request.PageSize = requests.NewInteger(100)
	request.Tag = &[]ecs.DescribeSecurityGroupsTag{{Key: poolTag, Value: c.cfg.poolID}}
	response, err := c.ecs.DescribeSecurityGroups(request)
	if err != nil {
		return "", err
	}
	for _, item := range response.SecurityGroups.SecurityGroup {
		if ecsTagValue(item.Tags.Tag, poolTag) == c.cfg.poolID {
			return item.SecurityGroupId, nil
		}
	}
	key := operationKey(c.cfg.poolID+":"+c.cfg.region, "setup-security-group", 0, 0)
	details := map[string]any{"vpc_id": vpcID, "ingress": "none"}
	if err := c.beginSetupOperation(ctx, key, "setup-security-group", details); err != nil {
		return "", err
	}
	create := ecs.CreateCreateSecurityGroupRequest()
	create.ClientToken = key
	create.VpcId = vpcID
	create.SecurityGroupName = "scan-platform-workers"
	create.Description = "Outbound-only worker security group; no SSH ingress"
	create.SecurityGroupType = "normal"
	create.Tag = &[]ecs.CreateSecurityGroupTag{{Key: poolTag, Value: c.cfg.poolID}, {Key: operationTag, Value: key}}
	created, err := c.ecs.CreateSecurityGroup(create)
	if err != nil {
		c.finishSetupOperation(ctx, key, err, nil)
		return "", err
	}
	c.finishSetupOperation(ctx, key, nil, map[string]any{"security_group_id": created.SecurityGroupId, "request_id": created.RequestId})
	return created.SecurityGroupId, nil
}

func (c *controller) discoverInstanceTypes(ctx context.Context) ([]string, error) {
	memories := []float64{c.cfg.minMemoryGiB}
	if c.cfg.minMemoryGiB < 4 {
		memories = append(memories, 4)
	}
	var preferred, fallback []string
	seen := make(map[string]bool)
	for _, memory := range memories {
		request := ecs.CreateDescribeAvailableResourceRequest()
		request.ZoneId = c.cfg.zone
		request.Cores = requests.NewInteger(2)
		request.Memory = requests.NewFloat(memory)
		request.InstanceChargeType = "PostPaid"
		request.SpotStrategy = "SpotAsPriceGo"
		request.SpotDuration = requests.NewInteger(0)
		request.ResourceType = "instance"
		request.DestinationResource = "InstanceType"
		request.IoOptimized = "optimized"
		response, err := c.ecs.DescribeAvailableResource(request)
		if err != nil {
			return nil, err
		}
		for _, zone := range response.AvailableZones.AvailableZone {
			if zone.ZoneId != c.cfg.zone || !strings.EqualFold(zone.Status, "Available") {
				continue
			}
			for _, resource := range zone.AvailableResources.AvailableResource {
				if resource.Type != "InstanceType" {
					continue
				}
				for _, supported := range resource.SupportedResources.SupportedResource {
					if !strings.EqualFold(supported.Status, "Available") || seen[supported.Value] {
						continue
					}
					seen[supported.Value] = true
					if supported.StatusCategory == "WithStock" {
						preferred = append(preferred, supported.Value)
					} else {
						fallback = append(fallback, supported.Value)
					}
				}
			}
		}
	}
	sort.Strings(preferred)
	sort.Strings(fallback)
	types := append(preferred, fallback...)
	types, err := c.filterInstanceTypes(ctx, types)
	if err != nil {
		return nil, err
	}
	if len(types) == 0 {
		return nil, fmt.Errorf("no available 2-core x86_64 non-burst instance type with at least %.1f GiB in %s", c.cfg.minMemoryGiB, c.cfg.zone)
	}
	if len(c.cfg.instanceTypes) > 0 {
		available := make(map[string]bool, len(types))
		for _, item := range types {
			available[item] = true
		}
		var ordered []string
		for _, item := range c.cfg.instanceTypes {
			if available[item] {
				ordered = append(ordered, item)
				delete(available, item)
			}
		}
		for _, item := range types {
			if available[item] {
				ordered = append(ordered, item)
			}
		}
		types = ordered
	}
	if len(types) > 5 {
		types = types[:5]
	}
	return types, nil
}

func (c *controller) filterInstanceTypes(ctx context.Context, candidates []string) ([]string, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	request := ecs.CreateDescribeInstanceTypesRequest()
	request.InstanceTypes = &candidates
	request.MaxResults = requests.NewInteger(100)
	response, err := c.ecs.DescribeInstanceTypes(request)
	if err != nil {
		return nil, err
	}
	compatible := make(map[string]float64)
	for _, spec := range response.InstanceTypes.InstanceType {
		architecture := strings.ToLower(strings.ReplaceAll(spec.CpuArchitecture, "-", "_"))
		x86 := architecture == "x86" || architecture == "x86_64" || architecture == "amd64"
		burstable := strings.HasPrefix(strings.ToLower(spec.InstanceTypeId), "ecs.t") ||
			strings.HasPrefix(strings.ToLower(spec.InstanceTypeFamily), "ecs.t") || spec.BaselineCredit > 0 || spec.InitialCredit > 0
		if spec.CpuCoreCount == 2 && spec.MemorySize >= c.cfg.minMemoryGiB && x86 && !burstable {
			compatible[spec.InstanceTypeId] = spec.MemorySize
		}
	}
	out := make([]string, 0, len(compatible))
	for _, candidate := range candidates {
		if _, ok := compatible[candidate]; ok {
			out = append(out, candidate)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return compatible[out[i]] < compatible[out[j]] })
	return out, nil
}

func (c *controller) discoverUbuntuImage(ctx context.Context, instanceType string) (string, error) {
	request := ecs.CreateDescribeImagesRequest()
	request.ImageOwnerAlias = "system"
	if c.cfg.imageID != "" {
		request.ImageId = c.cfg.imageID
	} else {
		request.ImageFamily = "acs:ubuntu_22_04_x64"
	}
	request.Architecture = "x86_64"
	request.OSType = "linux"
	request.Status = "Available"
	request.IsSupportCloudinit = requests.NewBoolean(true)
	request.InstanceType = instanceType
	request.PageSize = requests.NewInteger(100)
	response, err := c.ecs.DescribeImages(request)
	if err != nil {
		return "", err
	}
	images := response.Images.Image
	if len(images) == 0 {
		return "", errors.New("no official Ubuntu 22.04 x86_64 cloud-init image found")
	}
	for _, image := range images {
		if image.ImageFamily != "acs:ubuntu_22_04_x64" && !strings.Contains(strings.ToLower(image.ImageName), "ubuntu_22_04_x64") {
			return "", fmt.Errorf("image %s is not the official Ubuntu 22.04 x86_64 family", image.ImageId)
		}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].CreationTime > images[j].CreationTime })
	return images[0].ImageId, nil
}

func (c *controller) beginSetupOperation(ctx context.Context, key, operation string, details map[string]any) error {
	raw, _ := json.Marshal(details)
	_, err := c.db.Exec(ctx, `INSERT INTO cloud_operations
		(idempotency_key,provider,pool_id,operation,state,generation,amount,details)
		VALUES($1,'aliyun',$2,$3,'calling',0,1,$4)
		ON CONFLICT(idempotency_key) DO UPDATE SET state='calling',details=EXCLUDED.details,error='',updated_at=now()`,
		key, c.cfg.poolID, operation, raw)
	return err
}

func (c *controller) finishSetupOperation(ctx context.Context, key string, callErr error, result map[string]any) {
	state, errorText := "done", ""
	if callErr != nil {
		state, errorText = "unknown", shortError(callErr)
		var serverErr *sdkerrors.ServerError
		if errors.As(callErr, &serverErr) && serverErr.HttpStatus() > 0 && serverErr.HttpStatus() < 500 {
			state = "failed"
		}
	}
	details, _ := json.Marshal(result)
	_, _ = c.db.Exec(ctx, `UPDATE cloud_operations SET state=$2,details=CASE WHEN $3::jsonb='null' THEN details ELSE $3 END,
		error=$4,updated_at=now() WHERE idempotency_key=$1`, key, state, details, errorText)
}

func vpcTagValue(tags []vpc.Tag, key string) string {
	for _, tag := range tags {
		if tag.Key == key {
			return tag.Value
		}
	}
	return ""
}

func ecsTagValue(tags []ecs.Tag, key string) string {
	for _, tag := range tags {
		if tag.TagKey == key {
			return tag.TagValue
		}
		if tag.Key == key {
			return tag.Value
		}
	}
	return ""
}
