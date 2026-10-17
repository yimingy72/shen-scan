package cloud

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	sdkerrors "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cms"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
	"github.com/jackc/pgx/v5"

	"scanplatform/internal/control"
)

const (
	poolTag          = "scan-platform-pool"
	operationTag     = "scan-platform-operation"
	drainGrace       = 90 * time.Second
	registrationWait = 5 * time.Minute
)

type managedInstance struct {
	ecs.Instance
	operationKey string
	drainStarted *time.Time
}

type createDetails struct {
	InstanceType string `json:"instance_type"`
	VSwitchID    string `json:"vswitch_id"`
}

type operation struct {
	Key        string
	State      string
	Generation int64
	Amount     int
	Details    []byte
	UpdatedAt  time.Time
}

func newAliyunClients(c config) (*ecs.Client, *cms.Client, *vpc.Client, error) {
	var ecsClient *ecs.Client
	var cmsClient *cms.Client
	var vpcClient *vpc.Client
	var err error
	if c.securityToken == "" {
		ecsClient, err = ecs.NewClientWithAccessKey(c.region, c.accessKeyID, c.accessKeySecret)
		if err == nil {
			cmsClient, err = cms.NewClientWithAccessKey(c.region, c.accessKeyID, c.accessKeySecret)
		}
		if err == nil {
			vpcClient, err = vpc.NewClientWithAccessKey(c.region, c.accessKeyID, c.accessKeySecret)
		}
	} else {
		ecsClient, err = ecs.NewClientWithStsToken(c.region, c.accessKeyID, c.accessKeySecret, c.securityToken)
		if err == nil {
			cmsClient, err = cms.NewClientWithStsToken(c.region, c.accessKeyID, c.accessKeySecret, c.securityToken)
		}
		if err == nil {
			vpcClient, err = vpc.NewClientWithStsToken(c.region, c.accessKeyID, c.accessKeySecret, c.securityToken)
		}
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("initialize Alibaba Cloud SDK: %w", err)
	}
	// SDK v1 defaults to HTTP; credentials-derived signatures and bootstrap data
	// must always travel over TLS, including setup and read-only polling.
	ecsClient.GetConfig().WithScheme("HTTPS")
	cmsClient.GetConfig().WithScheme("HTTPS")
	vpcClient.GetConfig().WithScheme("HTTPS")
	ecsClient.SetConnectTimeout(5 * time.Second)
	ecsClient.SetReadTimeout(30 * time.Second)
	cmsClient.SetConnectTimeout(5 * time.Second)
	cmsClient.SetReadTimeout(30 * time.Second)
	vpcClient.SetConnectTimeout(5 * time.Second)
	vpcClient.SetReadTimeout(30 * time.Second)
	return ecsClient, cmsClient, vpcClient, nil
}

func (c *controller) reconcileAliyun(ctx context.Context, pool control.Pool) error {
	instances, err := c.describeManaged(ctx)
	if err != nil {
		return c.server.UpdatePoolRuntime(ctx, "aliyun", true, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, "list managed ECS instances: "+shortError(err))
	}
	if err := c.syncInstances(ctx, pool.Generation, instances); err != nil {
		return c.server.UpdatePoolRuntime(ctx, "aliyun", true, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, "reconcile known ECS instances: "+shortError(err))
	}
	workers, err := c.server.WorkerInstances(ctx)
	if err != nil {
		return c.server.UpdatePoolRuntime(ctx, "aliyun", true, pool.HealthyWorkers, pool.StartingWorkers, pool.DrainingWorkers, "load workers: "+shortError(err))
	}

	var warnings []error
	if err := c.reconcileQuotaStops(ctx, instances); err != nil {
		warnings = append(warnings, err)
	}
	if err := c.reconcileCreateOperations(ctx, pool, instances); err != nil {
		warnings = append(warnings, errors.New(shortError(err)))
	}
	if err := c.pollInterruptionEvents(ctx, instances); err != nil {
		warnings = append(warnings, fmt.Errorf("poll interruption events: %s", shortError(err)))
	}
	now := time.Now().UTC()
	for _, instance := range instances {
		if recycling(instance.Instance) {
			c.markDraining(ctx, instance, "Alibaba Cloud instance recycling lock", nil)
		}
		worker, registered := workers[instance.InstanceId]
		if registered && worker.Status == "offline" {
			c.markDraining(ctx, instance, "worker heartbeat lost", nil)
		}
		if !registered && strings.EqualFold(instance.Status, "Running") && now.Sub(instanceCreatedAt(instance.Instance)) >= registrationWait {
			c.markDraining(ctx, instance, "worker failed to register", nil)
		}
		if !pool.Enabled {
			c.markDraining(ctx, instance, "worker pool disabled", nil)
		}
	}

	reserved, err := c.reservedCapacity(ctx, instances)
	if err != nil {
		warnings = append(warnings, fmt.Errorf("load pending capacity: %w", err))
	}
	live := liveInstances(instances)
	if pool.Enabled && len(live)+reserved > pool.DesiredWorkers {
		candidates := append([]*managedInstance(nil), live...)
		sort.Slice(candidates, func(i, j int) bool {
			iHealthy := healthyWorker(workers[candidates[i].InstanceId])
			jHealthy := healthyWorker(workers[candidates[j].InstanceId])
			if iHealthy != jHealthy {
				return !iHealthy
			}
			return candidates[i].InstanceId > candidates[j].InstanceId
		})
		remaining := len(live) + reserved - pool.DesiredWorkers
		for _, instance := range candidates {
			if remaining == 0 {
				break
			}
			if instance.drainStarted == nil {
				c.markDraining(ctx, instance, "worker pool scale in", nil)
				remaining--
			}
		}
	}

	var releasable []string
	for _, instance := range live {
		if instance.drainStarted == nil {
			continue
		}
		active, taskErr := c.server.ActiveTasksForInstance(ctx, instance.InstanceId)
		if taskErr != nil {
			warnings = append(warnings, fmt.Errorf("check active tasks for %s: %w", instance.InstanceId, taskErr))
			continue
		}
		if active == 0 || now.Sub(*instance.drainStarted) >= drainGrace {
			releasable = append(releasable, instance.InstanceId)
		}
	}
	if len(releasable) > 0 {
		if err := c.deleteManaged(ctx, pool.Generation, releasable); err != nil {
			warnings = append(warnings, fmt.Errorf("release drained instances: %s", shortError(err)))
		}
	}

	reserved, reserveErr := c.reservedCapacity(ctx, instances)
	if reserveErr != nil {
		warnings = append(warnings, reserveErr)
	}
	if deficit := capacityDeficit(pool.DesiredWorkers, len(live), reserved); pool.Enabled && deficit > 0 {
		amount := min(10, deficit)
		if err := c.createInstances(ctx, pool.Generation, amount); err != nil {
			warnings = append(warnings, fmt.Errorf("create spot instances: %s", shortError(err)))
		}
		if current, err := c.reservedCapacity(ctx, instances); err == nil {
			reserved = current
		}
	}

	healthy, starting, draining := 0, reserved, 0
	for _, instance := range live {
		if instance.drainStarted != nil {
			draining++
		} else if healthyWorker(workers[instance.InstanceId]) {
			healthy++
		} else {
			starting++
		}
	}
	return c.server.UpdatePoolRuntime(ctx, "aliyun", true, healthy, starting, draining, joinErrors(warnings...))
}

func (c *controller) describeManaged(ctx context.Context) (map[string]*managedInstance, error) {
	out := make(map[string]*managedInstance)
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		request := ecs.CreateDescribeInstancesRequest()
		request.PageNumber = requests.NewInteger(page)
		request.PageSize = requests.NewInteger(100)
		request.Tag = &[]ecs.DescribeInstancesTag{{Key: poolTag, Value: c.cfg.poolID}}
		response, err := c.ecs.DescribeInstances(request)
		if err != nil {
			return nil, err
		}
		for _, item := range response.Instances.Instance {
			if tagValue(item, poolTag) != c.cfg.poolID {
				continue
			}
			copy := item
			out[item.InstanceId] = &managedInstance{Instance: copy, operationKey: tagValue(item, operationTag)}
		}
		if len(response.Instances.Instance) < 100 {
			break
		}
	}
	return out, nil
}

func (c *controller) syncInstances(ctx context.Context, generation int64, instances map[string]*managedInstance) error {
	visibleIDs := make([]string, 0, len(instances))
	for id, instance := range instances {
		visibleIDs = append(visibleIDs, id)
		if err := c.upsertVisibleInstance(ctx, generation, instance); err != nil {
			return err
		}
	}

	query := `SELECT instance_id FROM cloud_instances WHERE provider='aliyun' AND pool_id=$1 AND NOT release_confirmed`
	args := []any{c.cfg.poolID}
	if len(visibleIDs) > 0 {
		query += ` AND NOT(instance_id=ANY($2::text[]))`
		args = append(args, visibleIDs)
	}
	rows, err := c.db.Query(ctx, query, args...)
	if err != nil {
		return err
	}
	var missingIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		missingIDs = append(missingIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	if len(missingIDs) > 0 {
		verified, err := c.describeIDs(ctx, missingIDs)
		if err != nil {
			_, _ = c.db.Exec(ctx, `UPDATE cloud_instances SET state='Unknown',
				details=jsonb_set(details,'{reconcile_error}',to_jsonb($2::text),true),updated_at=now()
				WHERE provider='aliyun' AND pool_id=$1 AND instance_id=ANY($3::text[]) AND NOT release_confirmed`,
				c.cfg.poolID, shortError(err), missingIDs)
			return err
		}
		for _, id := range missingIDs {
			item, exists := verified[id]
			if !exists {
				_, err = c.db.Exec(ctx, `UPDATE cloud_instances SET
					missing_confirmations=missing_confirmations+1,
					release_confirmed=(missing_confirmations+1)>=2,
					state=CASE WHEN (missing_confirmations+1)>=2 THEN 'Released' ELSE 'Unknown' END,
					updated_at=now() WHERE instance_id=$1 AND provider='aliyun' AND pool_id=$2 AND NOT release_confirmed`, id, c.cfg.poolID)
				if err != nil {
					return err
				}
				continue
			}
			if tagValue(item, poolTag) != c.cfg.poolID {
				_, err = c.db.Exec(ctx, `UPDATE cloud_instances SET state='Unknown',missing_confirmations=0,
					release_confirmed=false,details=jsonb_set(details,'{reconcile_error}',to_jsonb($2::text),true),updated_at=now()
					WHERE instance_id=$1 AND provider='aliyun' AND pool_id=$3`, id, "instance exists but managed pool tag cannot be confirmed", c.cfg.poolID)
				if err != nil {
					return err
				}
				continue
			}
			copy := item
			instance := &managedInstance{Instance: copy, operationKey: tagValue(item, operationTag)}
			instances[id] = instance
			visibleIDs = append(visibleIDs, id)
			if err := c.upsertVisibleInstance(ctx, generation, instance); err != nil {
				return err
			}
		}
	}

	if len(visibleIDs) == 0 {
		return nil
	}
	rows, err = c.db.Query(ctx, `SELECT instance_id,drain_started FROM cloud_instances
		WHERE provider='aliyun' AND pool_id=$1 AND instance_id=ANY($2::text[])`, c.cfg.poolID, visibleIDs)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var drain *time.Time
		if err := rows.Scan(&id, &drain); err != nil {
			return err
		}
		if instance := instances[id]; instance != nil {
			instance.drainStarted = drain
		}
	}
	return rows.Err()
}

func instanceIsSpot(instance ecs.Instance) bool {
	if instance.SpotStrategy == "" {
		return instance.IsSpot
	}
	return instance.SpotStrategy == "SpotAsPriceGo" || instance.SpotStrategy == "SpotWithPriceLimit"
}

func (c *controller) upsertVisibleInstance(ctx context.Context, generation int64, instance *managedInstance) error {
	cores := instance.CPU
	if cores == 0 {
		cores = instance.Cpu
	}
	details, _ := json.Marshal(map[string]any{
		"instance_type": instance.InstanceType,
		"cpu_cores":     cores,
		"memory_mib":    instance.Memory,
		"zone_id":       instance.ZoneId,
		"creation_time": instance.CreationTime,
		"is_spot":       instanceIsSpot(instance.Instance),
		"spot_strategy": instance.SpotStrategy,
	})
	_, err := c.db.Exec(ctx, `INSERT INTO cloud_instances
		(instance_id,provider,pool_id,state,generation,operation_key,missing_confirmations,release_confirmed,details)
		VALUES($1,'aliyun',$2,$3,$4,$5,0,false,$6)
		ON CONFLICT(instance_id) DO UPDATE SET state=EXCLUDED.state,generation=EXCLUDED.generation,
		operation_key=EXCLUDED.operation_key,missing_confirmations=0,release_confirmed=false,
		details=EXCLUDED.details,updated_at=now()`, instance.InstanceId, c.cfg.poolID, instance.Status,
		generation, instance.operationKey, details)
	if err != nil {
		return err
	}
	_, err = c.db.Exec(ctx, `UPDATE workers SET spec=spec || jsonb_build_object(
		'instance_type',$2::text,'cpu_cores',$3::integer,'memory_mib',$4::integer,'cloud_provider','aliyun')
		WHERE instance_id=$1`, instance.InstanceId, instance.InstanceType, cores, instance.Memory)
	return err
}

func (c *controller) markDraining(ctx context.Context, instance *managedInstance, reason string, terminationAt *time.Time) {
	if instance.drainStarted != nil {
		return
	}
	now := time.Now().UTC()
	result, err := c.db.Exec(ctx, `UPDATE cloud_instances SET drain_started=COALESCE(drain_started,$2),
		details=jsonb_set(details,'{drain_reason}',to_jsonb($3::text),true),updated_at=now()
		WHERE instance_id=$1 AND provider='aliyun' AND pool_id=$4`, instance.InstanceId, now, reason, c.cfg.poolID)
	if err != nil || result.RowsAffected() != 1 {
		return
	}
	instance.drainStarted = &now
	if err := c.server.MarkInstanceDraining(ctx, instance.InstanceId, reason, terminationAt); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return
	}
}

func liveInstances(instances map[string]*managedInstance) []*managedInstance {
	out := make([]*managedInstance, 0, len(instances))
	for _, instance := range instances {
		switch strings.ToLower(instance.Status) {
		case "pending", "starting", "running", "stopping", "stopped":
			out = append(out, instance)
		}
	}
	return out
}

func healthyWorker(worker control.Worker) bool {
	return worker.Status == "ready" || worker.Status == "running"
}

func tagValue(instance ecs.Instance, key string) string {
	return ecsTagValue(instance.Tags.Tag, key)
}

func recycling(instance ecs.Instance) bool {
	for _, lock := range instance.OperationLocks.LockReason {
		if strings.EqualFold(lock.LockReason, "Recycling") {
			return true
		}
	}
	return false
}

func instanceCreatedAt(instance ecs.Instance) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04Z07:00", "2006-01-02T15:04Z"} {
		if created, err := time.Parse(layout, instance.CreationTime); err == nil {
			return created
		}
	}
	return time.Now().UTC()
}

func (c *controller) reconcileCreateOperations(ctx context.Context, pool control.Pool, instances map[string]*managedInstance) error {
	operationInstances := make(map[string]bool)
	for _, instance := range instances {
		if instance.operationKey != "" {
			operationInstances[instance.operationKey] = true
		}
	}
	rows, err := c.db.Query(ctx, `SELECT idempotency_key,state,generation,amount,details,updated_at
		FROM cloud_operations WHERE provider='aliyun' AND pool_id=$1 AND operation='create'
		AND state IN ('prepared','calling','unknown') ORDER BY created_at`, c.cfg.poolID)
	if err != nil {
		return err
	}
	var operations []operation
	for rows.Next() {
		var op operation
		if err := rows.Scan(&op.Key, &op.State, &op.Generation, &op.Amount, &op.Details, &op.UpdatedAt); err != nil {
			rows.Close()
			return err
		}
		operations = append(operations, op)
	}
	rows.Close()
	var errs []error
	for _, op := range operations {
		if operationInstances[op.Key] {
			_, err = c.db.Exec(ctx, `UPDATE cloud_operations SET state='done',error='',updated_at=now() WHERE idempotency_key=$1`, op.Key)
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if !pool.Enabled || pool.DesiredWorkers == 0 {
			_, err = c.db.Exec(ctx, `UPDATE cloud_operations SET state='abandoned',
				error='pool disabled or target is zero',updated_at=now() WHERE idempotency_key=$1`, op.Key)
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if op.State != "prepared" && time.Since(op.UpdatedAt) < 30*time.Second {
			continue
		}
		var details createDetails
		if err := json.Unmarshal(op.Details, &details); err != nil {
			errs = append(errs, fmt.Errorf("decode create operation %s: %w", op.Key, err))
			continue
		}
		if err := c.runCreateOperation(ctx, op, details); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.New(joinErrors(errs...))
	}
	return nil
}

func (c *controller) reservedCapacity(ctx context.Context, instances map[string]*managedInstance) (int, error) {
	var active int
	if err := c.db.QueryRow(ctx, `SELECT COALESCE(sum(amount),0) FROM cloud_operations
		WHERE provider='aliyun' AND pool_id=$1 AND operation='create' AND state IN ('prepared','calling','unknown')`, c.cfg.poolID).Scan(&active); err != nil {
		return 0, err
	}
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	var unconfirmed int
	query := `SELECT count(*) FROM cloud_instances WHERE provider='aliyun' AND pool_id=$1
		AND NOT release_confirmed`
	args := []any{c.cfg.poolID}
	if len(ids) > 0 {
		query += ` AND NOT(instance_id=ANY($2::text[]))`
		args = append(args, ids)
	}
	if err := c.db.QueryRow(ctx, query, args...).Scan(&unconfirmed); err != nil {
		return 0, err
	}
	return active + unconfirmed, nil
}

func capacityDeficit(desired, visible, reserved int) int {
	if deficit := desired - visible - reserved; deficit > 0 {
		return deficit
	}
	return 0
}

func (c *controller) createInstances(ctx context.Context, generation int64, amount int) error {
	if amount <= 0 {
		return nil
	}
	var sequence int
	if err := c.db.QueryRow(ctx, `SELECT count(*) FROM cloud_operations WHERE provider='aliyun'
		AND pool_id=$1 AND operation='create' AND generation=$2`, c.cfg.poolID, generation).Scan(&sequence); err != nil {
		return err
	}
	placements := len(c.cfg.instanceTypes) * len(c.cfg.vswitchIDs)
	choice := sequence % placements
	details := createDetails{
		InstanceType: c.cfg.instanceTypes[choice%len(c.cfg.instanceTypes)],
		VSwitchID:    c.cfg.vswitchIDs[(choice/len(c.cfg.instanceTypes))%len(c.cfg.vswitchIDs)],
	}
	key := operationKey(c.cfg.poolID, "create", generation, sequence+1)
	encoded, _ := json.Marshal(details)
	result, err := c.db.Exec(ctx, `INSERT INTO cloud_operations
		(idempotency_key,provider,pool_id,operation,state,generation,amount,details)
		VALUES($1,'aliyun',$2,'create','prepared',$3,$4,$5) ON CONFLICT DO NOTHING`,
		key, c.cfg.poolID, generation, amount, encoded)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return nil
	}
	return c.runCreateOperation(ctx, operation{Key: key, State: "prepared", Generation: generation, Amount: amount, Details: encoded}, details)
}

func (c *controller) runCreateOperation(ctx context.Context, op operation, details createDetails) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	script, err := BootstrapScript(BootstrapConfig{
		ControlURL: c.cfg.controlURL, ControlCAPEM: c.cfg.controlCAPEM, AgentPackageURL: c.cfg.agentPackageURL,
		AgentPackageHash: c.cfg.agentPackageHash, JoinToken: c.cfg.joinToken, ValidationFixture: c.cfg.validationFixture,
	})
	if err != nil {
		return err
	}
	_, _ = c.db.Exec(ctx, `UPDATE cloud_operations SET state='calling',error='',updated_at=now() WHERE idempotency_key=$1`, op.Key)
	request := ecs.CreateRunInstancesRequest()
	request.ClientToken = op.Key
	request.ImageId = c.cfg.imageID
	request.InstanceType = details.InstanceType
	request.VSwitchId = details.VSwitchID
	request.ZoneId = c.cfg.zone
	request.SecurityGroupId = c.cfg.securityGroupID
	request.InstanceChargeType = "PostPaid"
	request.InternetChargeType = "PayByTraffic"
	request.InternetMaxBandwidthOut = requests.NewInteger(c.cfg.publicBandwidth)
	request.IoOptimized = "optimized"
	request.SpotStrategy = "SpotAsPriceGo"
	request.SpotDuration = requests.NewInteger(0)
	request.SpotInterruptionBehavior = "Terminate"
	request.Amount = requests.NewInteger(op.Amount)
	request.MinAmount = requests.NewInteger(op.Amount)
	request.UniqueSuffix = requests.NewBoolean(true)
	request.InstanceName = "scan-worker"
	request.UserData = base64.StdEncoding.EncodeToString([]byte(script))
	request.Tag = &[]ecs.RunInstancesTag{{Key: poolTag, Value: c.cfg.poolID}, {Key: operationTag, Value: op.Key}}
	if c.cfg.priceLimit != nil {
		request.SpotStrategy = "SpotWithPriceLimit"
		request.SpotPriceLimit = requests.NewFloat(*c.cfg.priceLimit)
	}
	response, callErr := c.ecs.RunInstances(request)
	if callErr != nil {
		state := "unknown"
		var serverErr *sdkerrors.ServerError
		if errors.As(callErr, &serverErr) && serverErr.HttpStatus() > 0 && serverErr.HttpStatus() < 500 {
			state = "failed"
		}
		_, _ = c.db.Exec(ctx, `UPDATE cloud_operations SET state=$2,error=$3,updated_at=now() WHERE idempotency_key=$1`, op.Key, state, shortError(callErr))
		return callErr
	}
	ids := response.InstanceIdSets.InstanceIdSet
	if len(ids) == 0 {
		err := errors.New("RunInstances returned no instance IDs")
		_, _ = c.db.Exec(ctx, `UPDATE cloud_operations SET state='unknown',error=$2,updated_at=now() WHERE idempotency_key=$1`, op.Key, err.Error())
		return err
	}
	// Keep the operation reserved until every returned instance ID and the
	// completed operation are durably recorded together.
	tx, err := c.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, id := range ids {
		detailsJSON, _ := json.Marshal(map[string]any{"instance_type": details.InstanceType, "vswitch_id": details.VSwitchID})
		_, err = tx.Exec(ctx, `INSERT INTO cloud_instances
			(instance_id,provider,pool_id,state,generation,operation_key,details)
			VALUES($1,'aliyun',$2,'Starting',$3,$4,$5)
			ON CONFLICT(instance_id) DO UPDATE SET state='Starting',operation_key=$4,details=$5,updated_at=now()`,
			id, c.cfg.poolID, op.Generation, op.Key, detailsJSON)
		if err != nil {
			return err
		}
	}
	resultDetails, _ := json.Marshal(map[string]any{"instance_type": details.InstanceType, "vswitch_id": details.VSwitchID, "instance_ids": ids, "request_id": response.RequestId})
	if _, err = tx.Exec(ctx, `UPDATE cloud_operations SET state='done',details=$2,error='',updated_at=now() WHERE idempotency_key=$1`, op.Key, resultDetails); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (c *controller) deleteManaged(ctx context.Context, generation int64, ids []string) error {
	sort.Strings(ids)
	verified, err := c.describeIDs(ctx, ids)
	if err != nil {
		return err
	}
	for _, id := range ids {
		instance, ok := verified[id]
		if !ok {
			continue
		}
		if tagValue(instance, poolTag) != c.cfg.poolID {
			return fmt.Errorf("refusing to delete instance %s without managed pool tag", id)
		}
	}
	deleteIDs := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := verified[id]; ok {
			deleteIDs = append(deleteIDs, id)
		}
	}
	if len(deleteIDs) == 0 {
		return nil
	}
	key := operationKey(c.cfg.poolID, "delete:"+strings.Join(deleteIDs, ","), generation, 0)
	details, _ := json.Marshal(map[string]any{"instance_ids": deleteIDs})
	result, err := c.db.Exec(ctx, `INSERT INTO cloud_operations
		(idempotency_key,provider,pool_id,operation,state,generation,amount,details)
		VALUES($1,'aliyun',$2,'delete','prepared',$3,$4,$5) ON CONFLICT DO NOTHING`, key, c.cfg.poolID, generation, len(deleteIDs), details)
	if err != nil {
		return err
	}
	var state string
	var updated time.Time
	if result.RowsAffected() == 0 {
		if err := c.db.QueryRow(ctx, `SELECT state,updated_at FROM cloud_operations WHERE idempotency_key=$1`, key).Scan(&state, &updated); err != nil {
			return err
		}
		if state == "done" || (state == "unknown" && time.Since(updated) < 30*time.Second) {
			return nil
		}
	}
	_, _ = c.db.Exec(ctx, `UPDATE cloud_operations SET state='calling',error='',updated_at=now() WHERE idempotency_key=$1`, key)
	request := ecs.CreateDeleteInstancesRequest()
	request.ClientToken = key
	request.InstanceId = &deleteIDs
	request.Force = requests.NewBoolean(true)
	response, callErr := c.ecs.DeleteInstances(request)
	if callErr != nil {
		state = "unknown"
		var serverErr *sdkerrors.ServerError
		if errors.As(callErr, &serverErr) && serverErr.HttpStatus() > 0 && serverErr.HttpStatus() < 500 {
			state = "failed"
		}
		_, _ = c.db.Exec(ctx, `UPDATE cloud_operations SET state=$2,error=$3,updated_at=now() WHERE idempotency_key=$1`, key, state, shortError(callErr))
		return callErr
	}
	resultDetails, _ := json.Marshal(map[string]any{"instance_ids": deleteIDs, "request_id": response.RequestId, "task_group_id": response.TaskGroupId})
	_, err = c.db.Exec(ctx, `UPDATE cloud_operations SET state='done',details=$2,error='',updated_at=now() WHERE idempotency_key=$1`, key, resultDetails)
	return err
}

func (c *controller) describeIDs(ctx context.Context, ids []string) (map[string]ecs.Instance, error) {
	out := make(map[string]ecs.Instance, len(ids))
	for start := 0; start < len(ids); start += 100 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(start+100, len(ids))
		encoded, _ := json.Marshal(ids[start:end])
		request := ecs.CreateDescribeInstancesRequest()
		request.InstanceIds = string(encoded)
		request.PageSize = requests.NewInteger(100)
		response, err := c.ecs.DescribeInstances(request)
		if err != nil {
			return nil, err
		}
		for _, instance := range response.Instances.Instance {
			out[instance.InstanceId] = instance
		}
	}
	return out, nil
}

func operationKey(poolID, operation string, generation int64, sequence int) string {
	hash := sha256.Sum256([]byte(poolID + ":" + operation + ":" + strconv.FormatInt(generation, 10) + ":" + strconv.Itoa(sequence)))
	return "sp-" + hex.EncodeToString(hash[:20])
}

var sensitiveCloudValue = regexp.MustCompile(`(?i)(accesskeyid|accesskeysecret|signature|securitytoken|sts[_-]?token|authorization)(%3[dD]|["']?\s*[:=]\s*["']?)[^&\s"',}]+`)

func shortError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.ReplaceAll(err.Error(), "\n", " ")
	text = sensitiveCloudValue.ReplaceAllString(text, "$1$2[REDACTED]")
	if len(text) > 1000 {
		return text[:1000]
	}
	return text
}
