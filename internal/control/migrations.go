package control

const schema = `
CREATE TABLE IF NOT EXISTS runs (
  id text PRIMARY KEY,
  name text NOT NULL,
  targets jsonb NOT NULL,
  modes text[] NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','running','paused','cancelling','cancelled','completed','partial','failed')),
  error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE runs ADD COLUMN IF NOT EXISTS poc_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS rules_snapshot jsonb;
ALTER TABLE runs ALTER COLUMN rules_snapshot DROP NOT NULL;
ALTER TABLE runs ALTER COLUMN rules_snapshot DROP DEFAULT;
ALTER TABLE runs ADD COLUMN IF NOT EXISTS requires_httpx_cff boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS workers (
  id text PRIMARY KEY,
  instance_id text NOT NULL UNIQUE,
  hostname text NOT NULL,
  status text NOT NULL CHECK (status IN ('ready','running','draining','offline')),
  agent_version text NOT NULL,
  session_id text NOT NULL,
  token_hash bytea NOT NULL,
  last_heartbeat timestamptz NOT NULL DEFAULT now(),
  current_task_id text,
  az text NOT NULL DEFAULT '',
  spec jsonb NOT NULL DEFAULT '{}'::jsonb,
	metrics jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE runs ADD COLUMN IF NOT EXISTS last_claim_at timestamptz NOT NULL DEFAULT 'epoch';
ALTER TABLE runs ADD COLUMN IF NOT EXISTS last_claim_target_key text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS runs_active_claim_idx ON runs(last_claim_at,created_at,id) WHERE status IN ('pending','running');
ALTER TABLE workers ADD COLUMN IF NOT EXISTS metrics jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE workers ADD COLUMN IF NOT EXISTS maintenance boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS worker_pool (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  desired_workers integer NOT NULL DEFAULT 0 CHECK (desired_workers BETWEEN 0 AND 1000),
  enabled boolean NOT NULL DEFAULT false,
  generation bigint NOT NULL DEFAULT 1,
  healthy_workers integer NOT NULL DEFAULT 0,
  starting_workers integer NOT NULL DEFAULT 0,
  draining_workers integer NOT NULL DEFAULT 0,
  provider text NOT NULL DEFAULT '',
  configured boolean NOT NULL DEFAULT false,
  error text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO worker_pool (singleton) VALUES (true) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS tasks (
  id text PRIMARY KEY,
  run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  type text NOT NULL CHECK (type IN ('port','service','http','poc')),
  payload jsonb NOT NULL,
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','leased','completed','failed','cancelled')),
  attempt_no integer NOT NULL DEFAULT 0,
  worker_id text REFERENCES workers(id),
  session_id text,
  lease_until timestamptz,
  rate_until timestamptz,
  last_batch_seq integer NOT NULL DEFAULT -1,
  derived_key text NOT NULL,
  error text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  UNIQUE (run_id, derived_key)
);
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='tasks'::regclass AND conname='tasks_type_check'
  AND position('poc' in pg_get_constraintdef(oid))=0) THEN
  ALTER TABLE tasks DROP CONSTRAINT tasks_type_check;
 END IF;
 IF EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='tasks'::regclass AND conname='typeCheck') THEN
  ALTER TABLE tasks DROP CONSTRAINT "typeCheck";
 END IF;
	IF EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='tasks'::regclass AND conname='typecheck') THEN
	  ALTER TABLE tasks DROP CONSTRAINT typecheck;
	 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='tasks'::regclass AND conname='tasks_type_check') THEN
  ALTER TABLE tasks ADD CONSTRAINT tasks_type_check CHECK (type IN ('port','service','http','poc'));
 END IF;
END $$;
CREATE INDEX IF NOT EXISTS tasks_claim_idx ON tasks (type, created_at)
  WHERE state IN ('queued','leased');
CREATE INDEX IF NOT EXISTS tasks_run_idx ON tasks (run_id);
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS target_key text NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS execution_failures integer NOT NULL DEFAULT 0;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS first_started_at timestamptz;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS accepted_attempt_no integer;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS completion_id text;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS outcome text NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS coverage text NOT NULL DEFAULT 'unconfirmed';
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS reserved_until timestamptz;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS completion_scope_sha256 text;
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS completion_manifest jsonb;
CREATE TABLE IF NOT EXISTS task_item_completions (
 task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 work_key text NOT NULL,
 accepted_attempt_no integer NOT NULL,
 completion_id text NOT NULL UNIQUE,
 outcome text NOT NULL,
 coverage text NOT NULL,
 observation_id text NOT NULL,
 PRIMARY KEY(task_id,work_key)
);
UPDATE tasks SET accepted_attempt_no=attempt_no,completion_id=id||':'||attempt_no::text,
 coverage='complete' WHERE state='completed' AND accepted_attempt_no IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS tasks_completion_id_idx ON tasks(completion_id) WHERE completion_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS port_range_manifest (
 run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 target_key text NOT NULL,
 port_start integer NOT NULL CHECK(port_start BETWEEN 1 AND 65535),
 port_end integer NOT NULL CHECK(port_end BETWEEN port_start AND 65535),
 task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 PRIMARY KEY(run_id,target_key,port_start),
 UNIQUE(task_id,target_key)
);
CREATE TABLE IF NOT EXISTS target_quotas (
 epoch text PRIMARY KEY,
 task_id text NOT NULL,
 attempt_no integer NOT NULL,
 worker_id text NOT NULL REFERENCES workers(id),
 instance_id text NOT NULL,
 session_id text NOT NULL,
 scope text NOT NULL,
 dimension text NOT NULL,
 amount integer NOT NULL CHECK(amount>0),
 enforcement_class text NOT NULL DEFAULT 'cooperative',
 state text NOT NULL CHECK(state IN('reserved','active','suspect','revoking','released')),
 valid_until timestamptz NOT NULL,
 suspect_since timestamptz,
 revoke_deadline timestamptz,
 stop_evidence text NOT NULL DEFAULT '',
 released_at timestamptz,
 UNIQUE(task_id,attempt_no,worker_id,session_id,scope,dimension)
);
ALTER TABLE target_quotas DROP CONSTRAINT IF EXISTS target_quotas_task_id_fkey;
CREATE INDEX IF NOT EXISTS target_quotas_occupied_idx ON target_quotas(scope,dimension) WHERE state<>'released';
CREATE INDEX IF NOT EXISTS target_quotas_worker_idx ON target_quotas(worker_id,session_id,state);
CREATE TABLE IF NOT EXISTS port_start_tickets (
 worker_id text NOT NULL REFERENCES workers(id),session_id text NOT NULL,request_id text NOT NULL,
 root_task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 task_id text REFERENCES tasks(id) ON DELETE CASCADE,
 profile text NOT NULL, collect_until timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 PRIMARY KEY(worker_id,session_id,request_id)
);
CREATE INDEX IF NOT EXISTS tasks_run_target_idx ON tasks (run_id,target_key);
CREATE INDEX IF NOT EXISTS tasks_ready_target_idx ON tasks(run_id,target_key,created_at,id) WHERE state IN ('queued','leased');
CREATE INDEX IF NOT EXISTS tasks_worker_target_active_idx ON tasks(worker_id,session_id,target_key,type,lease_until) WHERE state='leased';
CREATE INDEX IF NOT EXISTS tasks_missing_target_idx ON tasks(id) WHERE target_key='';
CREATE TABLE IF NOT EXISTS task_targets (
 task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
 target_key text NOT NULL,
 PRIMARY KEY(task_id,target_key)
);
CREATE INDEX IF NOT EXISTS task_targets_key_idx ON task_targets(target_key,task_id);
CREATE TABLE IF NOT EXISTS run_target_policies (
 run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
 target_key text NOT NULL,
 open_flood boolean NOT NULL DEFAULT false,
 open_port_count integer NOT NULL DEFAULT 0,
 fingerprint_limit integer NOT NULL DEFAULT 1024,
 fingerprint_count integer NOT NULL DEFAULT 0,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(run_id,target_key)
);

CREATE TABLE IF NOT EXISTS claim_requests (
  worker_id text NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
  session_id text NOT NULL,
  request_id text NOT NULL,
  task_id text REFERENCES tasks(id),
  attempt_no integer,
	response jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (worker_id, session_id, request_id)
);
ALTER TABLE claim_requests ADD COLUMN IF NOT EXISTS response jsonb;

CREATE TABLE IF NOT EXISTS task_batches (
  task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  attempt_no integer NOT NULL,
  batch_seq integer NOT NULL CHECK (batch_seq >= 0),
  content_hash bytea NOT NULL,
  items jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (task_id, attempt_no, batch_seq)
);

CREATE TABLE IF NOT EXISTS assets (
  id text PRIMARY KEY,
  run_id text NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  task_id text NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  attempt_no integer NOT NULL,
  batch_seq integer NOT NULL,
  item_index integer NOT NULL,
  observation jsonb NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (task_id, attempt_no, batch_seq, item_index)
);
CREATE INDEX IF NOT EXISTS assets_run_idx ON assets (run_id, observed_at DESC);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS observation_raw bytea;
CREATE INDEX IF NOT EXISTS assets_task_attempt_idx ON assets (task_id,attempt_no);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS target_key text NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS assets_run_target_idx ON assets(run_id,target_key);
CREATE INDEX IF NOT EXISTS assets_missing_target_idx ON assets(id) WHERE target_key='';
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_statistic_ext WHERE stxrelid='assets'::regclass AND stxname='assets_observation_stats') THEN
  CREATE STATISTICS assets_observation_stats ON run_id,(observation->>'kind'),(COALESCE(observation->>'error','')),(COALESCE((observation->>'status_code')::int,0)) FROM assets;
  ANALYZE assets;
 END IF;
END $$;

CREATE TABLE IF NOT EXISTS rule_library (
  id text PRIMARY KEY,
  rule jsonb NOT NULL,
  deleted_at timestamptz,
  seed_version integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE rule_library ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE rule_library ADD COLUMN IF NOT EXISTS seed_version integer NOT NULL DEFAULT 0;
ALTER TABLE rule_library ADD COLUMN IF NOT EXISTS source_id text NOT NULL DEFAULT '';
ALTER TABLE rule_library ADD COLUMN IF NOT EXISTS upstream_hash text NOT NULL DEFAULT '';
ALTER TABLE rule_library ADD COLUMN IF NOT EXISTS local_modified boolean NOT NULL DEFAULT false;
ALTER TABLE rule_library ADD COLUMN IF NOT EXISTS enabled_override boolean;
ALTER TABLE rule_library ADD COLUMN IF NOT EXISTS upstream_retired boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS rule_library_kind_idx ON rule_library((rule->>'kind'));
CREATE INDEX IF NOT EXISTS rule_library_enabled_idx ON rule_library(((rule->>'enabled')::boolean));
CREATE INDEX IF NOT EXISTS rule_library_source_idx ON rule_library(source_id,id) WHERE source_id<>'';

CREATE TABLE IF NOT EXISTS rule_sources (
  id text PRIMARY KEY,
  name text NOT NULL,
  repository text NOT NULL,
  license text NOT NULL DEFAULT '',
  license_text text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'idle' CHECK(status IN ('idle','updating','ready','failed')),
  revision text NOT NULL DEFAULT '',
  converter_version text NOT NULL DEFAULT '',
  digest text NOT NULL DEFAULT '',
  stats jsonb NOT NULL DEFAULT '{"total":0,"accepted":0,"skipped":0,"reasons":{},"added":0,"updated":0,"unchanged":0,"preserved":0,"retired":0}'::jsonb,
  samples jsonb NOT NULL DEFAULT '[]'::jsonb,
  error text NOT NULL DEFAULT '',
  updated_at timestamptz
);
ALTER TABLE rule_sources ADD COLUMN IF NOT EXISTS converter_version text NOT NULL DEFAULT '';
INSERT INTO rule_sources(id,name,repository) VALUES
 ('wappalyzer','Wappalyzer fingerprints','https://github.com/projectdiscovery/wappalyzergo'),
 ('nuclei-templates','Nuclei templates','https://github.com/projectdiscovery/nuclei-templates')
ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,repository=EXCLUDED.repository;

CREATE TABLE IF NOT EXISTS rule_source_files (
  source_id text NOT NULL REFERENCES rule_sources(id) ON DELETE CASCADE,
  revision text NOT NULL,
  path text NOT NULL,
  sha256 text NOT NULL,
  data bytea NOT NULL,
  is_template boolean NOT NULL DEFAULT false,
  PRIMARY KEY(source_id,revision,path)
);
CREATE INDEX IF NOT EXISTS rule_source_files_revision_idx ON rule_source_files(source_id,revision,path);

CREATE TABLE IF NOT EXISTS rule_source_catalog (
  source_id text NOT NULL REFERENCES rule_sources(id) ON DELETE CASCADE,
  revision text NOT NULL,
  converter_version text NOT NULL,
  id text NOT NULL,
  rule jsonb NOT NULL,
  content_hash text NOT NULL,
  sanitized_fields text[] NOT NULL DEFAULT '{}',
  PRIMARY KEY(source_id,revision,converter_version,id)
);
ALTER TABLE rule_source_catalog ADD COLUMN IF NOT EXISTS sanitized_fields text[] NOT NULL DEFAULT '{}';
UPDATE rule_source_catalog SET rule=rule-'template' WHERE rule ? 'template';
CREATE INDEX IF NOT EXISTS rule_source_catalog_revision_idx ON rule_source_catalog(source_id,revision,converter_version,id);

`
