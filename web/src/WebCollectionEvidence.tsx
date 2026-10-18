import { Descriptions, Space, Tag, Typography } from 'antd'

type Response = { url?: string; status_code?: number; request_raw?: string; header_raw?: string; body?: string; body_storage?: string; body_sha256?: string; completeness?: string; error?: string }
type Redirect = { from_url: string; to_url?: string; status_code: number; outcome: string; attempt_index: number }
type Supplement = { url: string; outcome: string; reused?: boolean; error?: string; response?: Response; rule_results?: { rule_id: string; rule_revision: number; outcome: string }[]; storage?: { request_truncated?: boolean; headers_truncated?: boolean } }
type Envelope = {
  probe: { enrichment_profile?: string; input_url?: string; requests: number; attempts?: Response[]; redirects?: Redirect[] }
  requests_budget_used?: number; supplements?: Supplement[]
  supplement_plan?: { omitted_rules_count?: number }
  storage?: { headers_omitted?: boolean; omitted_supplements?: number; omitted_technologies?: number }
}
const labels: Record<string, string> = {
  followed: '已跟随', blocked_cross_origin: '超出同源范围', cross_origin: '超出同源范围', blocked_origin: '超出同源范围', blocked_scope: '超出范围', loop: '跳转循环', hop_limit: '已达跳转上限',
  skipped_budget: '请求预算已用完', skipped_limit: '补采数量受限', skipped_incomplete_reuse: '已有证据不完整',
  missing_location: '缺少跳转地址', invalid_location: '跳转地址无效', location_too_long: '跳转地址过长', canceled: '已停止', fetch_failed: '后续请求失败',
  matched: '产品确认', not_matched: '未匹配', partial: '响应不完整', error: '采集异常',
}
const label = (value: string) => labels[value] || value
const color = (value: string) => value === 'followed' || value === 'matched' ? 'green' : value === 'error' || value === 'fetch_failed' ? 'red' : value === 'not_matched' ? undefined : 'orange'

function ResponseDetails({ response, requestTruncated, headersTruncated }: { response?: Response; requestTruncated?: boolean; headersTruncated?: boolean }) {
  if (!response) return null
  let body = ''
  if (response.body) {
    try { body = new TextDecoder().decode(Uint8Array.from(atob(response.body), char => char.charCodeAt(0))) }
    catch { body = '正文编码无法解析' }
  }
  return <>
    {response.error && <div className="error-text">{response.error}</div>}
    {response.request_raw && <><div className="muted">请求{requestTruncated ? ' · 预览' : ''}</div><pre className="evidence-block">{response.request_raw}</pre></>}
    {response.header_raw && <><div className="muted">响应头{headersTruncated ? ' · 预览' : ''}</div><pre className="evidence-block">{response.header_raw}</pre></>}
    {body && <><div className="muted">已解码正文{response.body_storage === 'prefix' ? ' · 预览' : ''}</div><pre className="evidence-block">{body}</pre></>}
    {response.body_sha256 && <div className="cell-secondary mono break-text">正文 SHA-256 {response.body_sha256}</div>}
  </>
}

export function WebCollectionEvidence({ raw, finalURL }: { raw?: string; finalURL?: string }) {
  let value: Envelope
  try { value = JSON.parse(raw || '') as Envelope } catch { return null }
  if (value?.probe?.enrichment_profile !== 'bounded-enrichment-v1') return null
  const redirects = Array.isArray(value.probe.redirects) ? value.probe.redirects : []
  const supplements = Array.isArray(value.supplements) ? value.supplements : []
  return <section>
    <div className="filter-bar"><strong>采集路径</strong><Space size={4} wrap>
      <Tag>请求预算 {value.requests_budget_used ?? value.probe.requests} / 8</Tag>
      <Tag>跟随 {redirects.filter(step => step.outcome === 'followed').length} 跳</Tag>
      {!!supplements.length && <Tag>补采记录 {supplements.length}</Tag>}
    </Space></div>
    {value.probe.input_url && value.probe.input_url !== finalURL && <Descriptions size="small" column={1} items={[{ key: 'entry', label: '原始入口', children: <Typography.Text copyable className="mono break-text">{value.probe.input_url}</Typography.Text> }]} />}
    {redirects.map((step, index) => <details className="verification-check" key={`redirect-${index}`}>
      <summary><Tag color={color(step.outcome)}>{label(step.outcome)}</Tag><span className="mono break-text">{step.status_code} {step.from_url} → {step.to_url || '—'}</span></summary>
      <ResponseDetails response={value.probe.attempts?.[step.attempt_index]} headersTruncated={value.storage?.headers_omitted} requestTruncated={value.storage?.headers_omitted} />
    </details>)}
    {supplements.map((item, index) => <details className="verification-check" key={`supplement-${index}`}>
      <summary><Tag color={color(item.outcome)}>{label(item.outcome)}</Tag>{item.reused && <Tag>复用响应</Tag>}<span className="mono break-text">GET {item.url}</span></summary>
      {item.error && <div className="error-text">{item.error}</div>}
      {item.rule_results?.map(result => <div className="cell-secondary" key={result.rule_id}><span className="mono">{result.rule_id} · v{result.rule_revision}</span> · {label(result.outcome)}</div>)}
      <ResponseDetails response={item.response} requestTruncated={item.storage?.request_truncated} headersTruncated={item.storage?.headers_truncated} />
    </details>)}
    {!!value.supplement_plan?.omitted_rules_count && <div className="compact-note">候选上限之外还有 {value.supplement_plan.omitted_rules_count} 条规则未检查。</div>}
    {!!value.storage?.omitted_supplements && <div className="compact-note">存储上限省略了 {value.storage.omitted_supplements} 条补采记录。</div>}
    {!!value.storage?.omitted_technologies && <div className="compact-note">存储上限省略了 {value.storage.omitted_technologies} 条指纹展示记录。</div>}
  </section>
}
