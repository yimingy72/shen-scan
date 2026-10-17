package control

import (
	"context"
	"sort"

	"github.com/jackc/pgx/v5"
)

const openFloodThreshold = 1024

// Port evidence is never capped. Dense targets get a bounded, explicit
// fingerprint policy so one wildcard SYN responder cannot fill every queue.
func fingerprintPorts(ctx context.Context, tx pgx.Tx, runID, target string, ports []int) ([]int, error) {
	// All intake paths share one unique positive-port set and downstream budget.
	// Already scheduled endpoints were removed by the stable service-work binding.
	var priorPorts, alreadySelected, limit int
	err := tx.QueryRow(ctx, `SELECT count(DISTINCT port) FROM (
        SELECT port FROM port_positive_receipts WHERE run_id=$1 AND target_key=$2
        UNION SELECT (a.observation->>'port')::int FROM assets a JOIN tasks t ON t.id=a.task_id
        WHERE a.run_id=$1 AND a.target_key=$2 AND a.observation->>'kind'='port' AND t.state='completed'
        AND a.attempt_no=COALESCE(t.accepted_attempt_no,t.attempt_no) AND COALESCE(a.observation->>'error','')=''
        UNION SELECT unnest($3::int[])) positive`, runID, target, ports).Scan(&priorPorts)
	if err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO run_target_policies(run_id,target_key,open_flood,open_port_count,fingerprint_limit)
        VALUES($1,$2,$3,$4,1024) ON CONFLICT(run_id,target_key) DO UPDATE SET
        open_flood=run_target_policies.open_flood OR EXCLUDED.open_flood,
        open_port_count=GREATEST(run_target_policies.open_port_count,EXCLUDED.open_port_count),updated_at=now()
        RETURNING fingerprint_limit,fingerprint_count`, runID, target, priorPorts > openFloodThreshold, priorPorts).Scan(&limit, &alreadySelected)
	if err != nil {
		return nil, err
	}
	remaining := max(0, limit-alreadySelected)
	selected := []int{}
	if remaining > 0 {
		selected = sampleFingerprintPorts(ports, remaining)
	}
	_, err = tx.Exec(ctx, `UPDATE run_target_policies SET fingerprint_count=fingerprint_count+$3 WHERE run_id=$1 AND target_key=$2`, runID, target, len(selected))
	return selected, err
}

func sampleFingerprintPorts(ports []int, limit int) []int {
	if len(ports) <= limit {
		return ports
	}
	available := make(map[int]bool, len(ports))
	for _, port := range ports {
		available[port] = true
	}
	chosen := make(map[int]bool, limit)
	for _, port := range []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017} {
		if len(chosen) < limit && available[port] {
			chosen[port] = true
		}
	}
	remaining := limit - len(chosen)
	for i := 0; i < remaining; i++ {
		index := i * (len(ports) - 1) / max(remaining-1, 1)
		chosen[ports[index]] = true
	}
	for _, port := range ports {
		if len(chosen) >= limit {
			break
		}
		chosen[port] = true
	}
	out := make([]int, 0, len(chosen))
	for port := range chosen {
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}
