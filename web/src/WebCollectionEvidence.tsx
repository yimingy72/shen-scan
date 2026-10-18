import { Descriptions, Space, Tag, Typography } from 'antd'
import type { Asset, WebScanOptions, WebStage } from './api'

type Response = { url?: string; status_code?: number; request_raw?: string; header_raw?: string; body?: string; body_storage?: string; body_sha256?: string; completeness?: string; error?: string }
type Redirect = { from_url: string; to_url?: string; status_code: number; outcome: string; attempt_index: number }
type Supplement = { url: string; outcome: string; reused?: boolean; error?: string; response?: Response; rule_results?: { rule_id: string; rule_revision: number; outcome: string }[]; storage?: { request_truncated?: boolean; headers_truncated?: boolean } }
type Envelope = {
  probe: { web_scan_options?: WebScanOptions; execution_profile?: string; capability_gaps?: string[]; sdk_result?: unknown; enrichment_profile?: string; input_url?: string; requests: number; attempts?: Response[]; redirects?: Redirect[] }
  fingerprint?: { matches?: { name: string; engine: string; candidate?: boolean; candidate_reason?: string }[]; active?: { complete: boolean; requests: number; completed_rule_ids?: string[]; remaining_rule_ids?: string[]; stop_reason?: string; rules?: { rule_id: string; status: string; requests: number; error?: string }[]; responses?: Response[] } }
  requests_budget_used?: number; supplements?: Supplement[]
  supplement_plan?: { omitted_rules_count?: number }
  storage?: { headers_omitted?: boolean; omitted_supplements?: number; omitted_technologies?: number }
  browser?: { js_dom_enabled?: boolean; js_dom?: WebStage; screenshot?: WebStage; complete: boolean; browser_version?: string; total_rules: number; evaluated_rules: number; unsupported_rules: number; incomplete_rules: number; requests: number; stop_reason?: string; error?: string; sample_window?: string; plan_sha256?: string; matches?: { name: string; version?: string; evidence?: unknown }[]; rules?: { rule_id: string; status: string; error?: string }[]; blocked?: { url: string; method: string; reason: string }[]; attempts?: Response[] }
}
type BrowserStage = NonNullable<Asset['browser']>
const browserReasons: Record<string, string> = { 'browser-unavailable': '浏览器依赖或隔离不可用', 'browser-timeout': '观测时间已用完', 'browser-error': '浏览器执行异常', 'browser-network-partial': '部分页面资源未取得', 'browser-rules-partial': '部分规则未完成', 'browser-output-partial': '证据超过存储上限', 'sample-window-complete': '观测窗口内完成', 'cumulative-budget': '累计请求额度已用完', 'cumulative-deadline': '执行截止时间已到' }

function BrowserEvidence({ value, stage }: { value?: Envelope['browser']; stage?: BrowserStage }) {
  if ((!value && !stage) || value?.js_dom_enabled === false) return null
  const state = value?.js_dom?.state || stage?.js_dom?.state || stage?.state || (value?.complete ? 'complete' : 'partial')
  if (state === 'not_selected') return null
  if (state === 'not_applicable') return <div className="compact-note">此入口无需浏览器补充。</div>
  return <section><div className="filter-bar"><strong>Wapp JS / DOM</strong><Space size={4}><Tag color={state === 'complete' ? 'success' : state === 'pending' ? 'processing' : 'warning'}>{{ pending: '等待补充', complete: '观测完成', partial: '部分完成' }[state] || state}</Tag>{value && <Tag>{value.requests} 次请求</Tag>}</Space></div>
    {state === 'pending' && <div className="compact-note">基础 HTTP 结果已就绪，浏览器使用独立并发槽继续识别。</div>}
    {value && <><div className="compact-note">已求值 {value.evaluated_rules} / {value.total_rules} 条 · 不兼容 {value.unsupported_rules} · 未完成 {value.incomplete_rules}{value.browser_version ? ` · ${value.browser_version}` : ''}</div>
      {state !== 'complete' && <div className="compact-note amber">{value.js_dom?.error || value.error || browserReasons[value.js_dom?.stop_reason || value.stop_reason || ''] || value.stop_reason}</div>}
      <details className="verification-check"><summary>匹配与执行证据</summary><div className="compact-note">{value.sample_window} · 计划 {value.plan_sha256?.slice(0, 16)}</div><pre className="evidence-block">{JSON.stringify({ matches: value.matches || [], rules: value.rules || [] }, null, 2)}</pre></details>
      {!!value.blocked?.length && <details className="verification-check"><summary>未加载资源 · {value.blocked.length}</summary><pre className="evidence-block">{JSON.stringify(value.blocked, null, 2)}</pre></details>}
    </>}
  </section>
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

export function WebCollectionEvidence({ raw, finalURL, stage, options }: { raw?: string; finalURL?: string; stage?: BrowserStage; options?: WebScanOptions }) {
  let value: Envelope
  try { value = JSON.parse(raw || '') as Envelope } catch { return null }
  if (value?.probe?.execution_profile === 'web-full-v2') {
    const active = value.fingerprint?.active
    const selected = options || value.probe.web_scan_options
    const gaps = (value.probe.capability_gaps || []).filter(gap => !['http2-probe', 'unsafe', 'ztls', 'headless'].includes(gap) && !(gap === 'wappalyzer-browser-js-dom' && (selected?.js_dom === false || value.browser || stage)))
    return <section><div className="filter-bar"><strong>HTTP 执行记录</strong><Space size={4} wrap><Tag>httpx 完整 Runner</Tag><Tag>已授权请求 {value.requests_budget_used ?? value.probe.requests}</Tag>{selected?.active === false ? <Tag>主动指纹未开启</Tag> : <Tag color={active?.complete ? 'success' : 'warning'}>主动指纹{active?.complete ? '完成' : '未完成'}</Tag>}{selected?.passive === false && <Tag>被动指纹未开启</Tag>}</Space></div>
      {selected?.active !== false && <div className="compact-note">主动执行单元：已完成 {active?.completed_rule_ids?.length || 0} · 剩余 {active?.remaining_rule_ids?.length || 0} · 本段网络请求 {active?.requests || 0}{active?.stop_reason ? ` · ${active.stop_reason}` : ''}</div>}
      {!!gaps.length && <div className="compact-note amber">{gaps.map(gap => gap === 'wappalyzer-browser-js-dom' ? 'Wappalyzer 的浏览器 JS / DOM 条件未执行；已取得的响应指纹仍然有效。' : gap).join(' · ')}</div>}
      {selected?.js_dom !== false && <BrowserEvidence value={value.browser} stage={stage} />}
      {!!value.fingerprint?.matches?.some(match => match.candidate) && <div className="compact-note amber">候选指纹不触发 PoC：{value.fingerprint.matches.filter(match => match.candidate).map(match => `${match.name}（${match.candidate_reason === 'goby_rdp_inside_word_required' ? '仅命中单词内部 rdp 子串' : match.candidate_reason || '需独立证据确认'}）`).join(' · ')}</div>}
      <details className="verification-check"><summary>httpx 元信息</summary><pre className="evidence-block">{JSON.stringify(value.probe.sdk_result, null, 2)}</pre></details>
      {selected?.active !== false && <details className="verification-check"><summary>主动规则执行结局</summary><pre className="evidence-block">{JSON.stringify(active?.rules || [], null, 2)}</pre></details>}
      <details className="verification-check"><summary>逐请求报文 · {(value.probe.attempts?.length || 0) + (active?.responses?.length || 0)} 条</summary>{[...(value.probe.attempts || []), ...(active?.responses || [])].map((response, index) => <details className="verification-check" key={index}><summary><Tag>{response.status_code || '异常'}</Tag><span className="mono break-text">{response.url}</span></summary><ResponseDetails response={response} /></details>)}</details>
    </section>
  }
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
