package cloud

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Reuse the pool reconciler to recover allocations whose old tools may still
// be sending. A delete request, absent heartbeat or expired lease is not proof
// of termination. syncInstances confirms disappearance with repeated direct
// instance lookups; only that terminal evidence releases the captured session.
func (c *controller) reconcileQuotaStops(ctx context.Context, instances map[string]*managedInstance) error {
	allocations, err := c.server.UnknownWorkerQuotas(ctx)
	if err != nil {
		return fmt.Errorf("load unknown worker allocations: %w", err)
	}
	seen := map[string]bool{}
	var failures []error
	for _, allocation := range allocations {
		key := allocation.InstanceID + "/" + allocation.SessionID
		if seen[key] {
			continue
		}
		seen[key] = true
		var released bool
		var confirmations int
		err := c.db.QueryRow(ctx, `SELECT release_confirmed,missing_confirmations FROM cloud_instances
 WHERE provider='aliyun' AND pool_id=$1 AND instance_id=$2`, c.cfg.poolID, allocation.InstanceID).Scan(&released, &confirmations)
		if errors.Is(err, pgx.ErrNoRows) {
			failures = append(failures, fmt.Errorf("blocked_quota_unknown: instance %s is not in the managed pool", allocation.InstanceID))
			continue
		}
		if err != nil {
			return err
		}
		instance := instances[allocation.InstanceID]
		if released && confirmations >= 2 && instance == nil {
			evidence := fmt.Sprintf("aliyun instance %s termination confirmed by %d direct absence checks at %s", allocation.InstanceID, confirmations, time.Now().UTC().Format(time.RFC3339))
			if err := c.server.ConfirmWorkerStopped(ctx, allocation.InstanceID, allocation.SessionID, evidence); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		if instance != nil && tagValue(instance.Instance, poolTag) == c.cfg.poolID {
			c.markDraining(ctx, instance, "unconfirmed task stop; quota recovery", nil)
			if instance.drainStarted != nil {
				if err := c.server.MarkWorkerQuotaRevoking(ctx, allocation.InstanceID, allocation.SessionID); err != nil {
					failures = append(failures, err)
				}
			}
		}
		if !allocation.RevokeDeadline.IsZero() && time.Now().After(allocation.RevokeDeadline) {
			failures = append(failures, fmt.Errorf("blocked_quota_unknown: awaiting confirmed stop of %s session %s", allocation.InstanceID, allocation.SessionID))
		}
	}
	return errors.Join(failures...)
}
