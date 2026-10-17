export interface Run {
  id: string
  name: string
  targets: string[]
  input_count?: number
  poc_enabled?: boolean
  finding_count?: number
  verification_finding_count?: number
  discovery_match_count?: number
  check_match_count?: number
  poc_checked_count?: number
  modes: ('port' | 'http')[]
  status: string
  created_at: string
  updated_at: string
  task_total: number
  task_done: number
  task_failed: number
  asset_count: number
  target_count: number
  target_done: number
  open_port_count: number
  http_count: number
  error?: string
}

export interface Technology {
  name: string
  version?: string
  evidence?: string
}

export interface Verification {
  id: string; cves: string[]; category: string; evidence_level: string; summary: string; references?: string[]
  source_pin: { source_id: string; repository: string; revision: string; path: string; sha256: string }
}

export interface Asset {
  positive_port_receipt?: { id: string; source_task_id: string; source_attempt_no: number; batch_seq: number; batch_sha256: string; accepted_at: string; coverage_independent: boolean }
  purpose?: string
  verification?: Verification
  checks?: { request_raw: string; response_raw: string }[]
  matched_products?: string[]
  trigger_reason?: string
  rule_id?: string
  rule_name?: string
  rule_revision?: number
  engine?: string
  severity?: string
  finding_status?: string
  evidence?: string
  source_target?: string
  id: string
  run_id: string
  observed_at: string
  kind: 'port' | 'service' | 'http' | 'poc'
  target: string
  ip: string
  port: number
  protocol: string
  service?: string
  product?: string
  version?: string
  url?: string
  status_code?: number
  title?: string
  server?: string
  technologies?: Technology[]
  headers?: Record<string, string[]>
  body_excerpt?: string
  banner?: string
  request_raw?: string
  response_raw?: string
  truncated?: boolean
  error?: string
}

export interface Worker {
  maintenance?: boolean
  session_id?: string
  id: string
  instance_id: string
  hostname: string
  status: string
  agent_version: string
  last_heartbeat: string
  current_task_id?: string
  az?: string
  spec?: Record<string, string | number | null>
  metrics?: Record<string, number>
  active_tasks?: { id: string; type: string; target: string; targets?: string[]; run_id: string; run_name: string }[]
}

export interface TargetResult {
  port_coverage?: 'complete' | 'partial' | 'unconfirmed' | 'not_scanned'
  target: string; state: string; port_state: string; task_total: number; task_done: number; task_failed: number; failure_reason?: string
  open_port_count: number; ports: number[]; open_flood?: boolean; fingerprint_limited?: boolean; fingerprint_count?: number; http_count: number; error_count: number; ips: string[]
  services: string[]; products: string[]; technologies: string[]; titles: string[]; updated_at: string
}
export interface PortResult {
  port_observation_id?: string
  positive_port_receipt_id?: string
  port: number; is_open: boolean; service?: string; product?: string; version?: string; error?: string
  service_observation_id?: string
  http: { id: string; url: string; title?: string; status_code: number; technologies?: Technology[] }[]
}
export interface CloudAccount {
  name: string; account_id: string; region: string; zone: string; verified_at?: string; revision: number
}
export interface CloudConfig {
  account: CloudAccount; has_credentials: boolean; access_key_masked: string; ready: boolean; error?: string
  resources: { region: string; zone: string; vpc_id?: string; vswitch_ids?: string[]; security_group_id?: string; image_id?: string; instance_types?: string[]; vpc_cidr?: string; vswitch_cidr?: string }
}
export interface CloudInstance {
  instance_id: string; state: string; released: boolean; drain_started?: string; created_at: string; updated_at: string
  details: Record<string, string | number | boolean | undefined>
}
export interface PageData<T> { items: T[]; total: number }

export interface Pool {
  desired_workers: number
  enabled: boolean
  generation: number
  healthy_workers: number
  starting_workers: number
  draining_workers: number
  provider: string
  configured: boolean
  error?: string
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
  }
}

export class ApiClient {
  constructor(
    private readonly base: string,
    private readonly token: string,
  ) {}

  async blob(path: string): Promise<Blob> {
    const response = await fetch(`${this.base}${path}`, {
      signal: AbortSignal.timeout(120000),
      headers: { Authorization: `Bearer ${this.token}` },
    })
    if (!response.ok) {
      const data = await response.json().catch(() => undefined)
      throw new ApiError(data?.error || `下载失败（HTTP ${response.status}）`, response.status)
    }
    return response.blob()
  }

  request<T>(path: string, options: RequestInit = {}): Promise<T> {
    return fetch(`${this.base}${path}`, {
      ...options,
      signal: options.signal ?? AbortSignal.timeout(90000),
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${this.token}`,
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...options.headers,
      },
    }).then(async (response) => {
      const text = await response.text()
      let data: unknown
      try {
        data = text ? JSON.parse(text) : undefined
      } catch {
        data = undefined
      }
      if (!response.ok) {
        const message =
          typeof data === 'object' && data && 'error' in data
            ? String((data as { error: unknown }).error)
            : `请求失败（HTTP ${response.status}）`
        throw new ApiError(message, response.status)
      }
      return data as T
    })
  }
}

export const formatTime = (value?: string) => {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString('zh-CN', { hour12: false })
}

export type RuleKind = 'http' | 'port' | 'poc'
export interface NucleiMetadata {
  template_id: string; execution_profile?: string; content_sha256?: string; catalog_only?: boolean
  protocols?: string[]; raw?: boolean; capabilities?: string[]; request_count?: number
  default_disabled_reason?: string; runtime_reason?: string; info?: unknown; classification?: unknown
}
export interface LibraryRule {
  purpose?: string; verification?: Verification
  nuclei?: NucleiMetadata; execution_profile?: string; template_id?: string; content_sha256?: string
  fingerprint?: Record<string, unknown>; execution_available?: boolean; runtime_reason?: string
  id: string; kind: RuleKind; name: string; description?: string; engine: 'native' | 'nuclei' | 'httpx-cff'
  severity: string; enabled: boolean; builtin: boolean; revision: number; tags?: string[]; source?: string
  definition?: Record<string, unknown>; template?: string; match_summary?: string; applies_to?: string[]; source_id?: string
}
