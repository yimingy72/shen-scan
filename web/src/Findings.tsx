import { useState } from 'react'
import { Button, Pagination, Segmented, Select, Table, Tag, Tooltip } from 'antd'
import { ApiClient, type Asset, type PageData } from './api'
import { LoadError, NoData, number, useLoad } from './ui'
import { RulePurpose, Severity, severityNames } from './Library'

export function findingEvidence(value = '') {
  const marker = value.indexOf('; JSONL: ')
  return marker < 0 ? { summary: value, jsonl: '' } : { summary: value.slice(0, marker), jsonl: value.slice(marker + 9) }
}
export function triggerLabel(reason = '') {
  const labels: Record<string, string> = { http_technology: 'HTTP 指纹匹配', service_product: '端口产品匹配', explicit_unbound_rule: '手动选择通用检查', legacy_all_enabled: '历史任务规则策略' }
  return reason.split('+').map(value => labels[value] || value).join(' + ')
}
export function FindingStatus({ value, purpose }: { value?: string; purpose?: string }) {
  return <Tag color={value === 'matched' ? 'warning' : value === 'error' ? 'error' : undefined}>{value === 'matched' ? (purpose === 'verification' ? '已验证' : '发现') : value === 'error' ? '检测错误' : value === 'not_matched' ? (purpose === 'verification' ? '未证实' : '未命中') : '待确认'}</Tag>
}
export function FindingsTable({ api, runId, polling, openEvidence }: { api: ApiClient; runId: string; polling: boolean; openEvidence: (id: string) => void }) {
  const [status, setStatus] = useState('matched')
  const [severity, setSeverity] = useState('')
  const [purpose, setPurpose] = useState('')
  const [page, setPage] = useState(1)
  const data = useLoad<PageData<Asset> & { summary: { matched: number; not_matched: number; error: number; verification_matched: number; discovery_matched: number } }>(api, `/runs/${encodeURIComponent(runId)}/findings?${new URLSearchParams({ status, severity, purpose, limit: '50', offset: String((page - 1) * 50) })}`, polling ? 10000 : 0)
  const checked = data.data ? data.data.summary.matched + data.data.summary.not_matched + data.data.summary.error : 0
  const emptyText = checked ? (status === 'matched' ? '当前没有命中项；可查看未命中和检测错误' : '没有符合条件的检查记录') : polling ? '等待符合关联指纹的端点产生检查结果' : '本任务没有 PoC 检查记录；未匹配规则的端点会跳过'
  const columns = [
    { title: '检查项', key: 'rule', width: 270, render: (_: unknown, a: Asset) => <div className="name-cell"><button className="text-link strong" onClick={() => openEvidence(a.id)}>{a.rule_name || a.rule_id || '未知规则'}</button><span><RulePurpose value={a.purpose} /></span><span className="cell-secondary mono">{a.rule_id} · v{a.rule_revision}</span></div> },
    { title: '目标 / URL', key: 'url', width: 300, render: (_: unknown, a: Asset) => <div className="name-cell"><span className="mono line-clamp">{a.url || a.target}</span><span className="cell-secondary mono">来源 {a.source_target || a.target}</span></div> },
    { title: '级别', dataIndex: 'severity', width: 75, render: (v: string) => <Severity value={v} /> },
    { title: '状态', dataIndex: 'finding_status', width: 95, render: (v: string, a: Asset) => <FindingStatus value={v} purpose={a.purpose} /> },
    { title: '引擎', dataIndex: 'engine', width: 80, render: (v: string) => <Tag>{v === 'nuclei' ? 'Nuclei' : '原生'}</Tag> },
    { title: '依据 / 异常', key: 'evidence', width: 260, render: (_: unknown, a: Asset) => <div className="name-cell"><Tooltip title={a.error || findingEvidence(a.evidence).summary}><span className={`line-clamp ${a.error ? 'error-text' : 'muted'}`}>{a.error || findingEvidence(a.evidence).summary || '—'}</span></Tooltip>{a.trigger_reason && <Tooltip title={triggerLabel(a.trigger_reason)}><span className="cell-secondary line-clamp">{a.matched_products?.length ? `关联指纹：${a.matched_products.join(' / ')}` : triggerLabel(a.trigger_reason)}</span></Tooltip>}</div> },
    { title: '', key: 'details', width: 65, render: (_: unknown, a: Asset) => <Button size="small" type="link" onClick={() => openEvidence(a.id)}>详情</Button> },
  ]
  return <><div className="filter-bar"><Segmented value={status} onChange={v => { setStatus(v); setPage(1) }} options={[{ label: `命中 ${number(data.data?.summary.matched)}`, value: 'matched' }, { label: `检测错误 ${number(data.data?.summary.error)}`, value: 'error' }, { label: `未命中 ${number(data.data?.summary.not_matched)}`, value: 'not_matched' }, { label: '全部', value: 'all' }]} /><Select aria-label="结果类型" value={purpose} onChange={value => { setPurpose(value); setPage(1) }} style={{ width: 160 }} options={[{ value: '', label: '全部检查' }, { value: 'verification', label: '漏洞验证' }, { value: 'discovery', label: '发现检查' }]} /><span className="bar-spacer" /><Select aria-label="风险级别" value={severity} onChange={v => { setSeverity(v); setPage(1) }} style={{ width: 120 }} options={[{ label: '全部级别', value: '' }, ...Object.entries(severityNames).map(([value, label]) => ({ value, label }))]} /></div><LoadError error={data.error} retry={() => void data.reload()} /><Table rowKey="id" size="small" tableLayout="fixed" columns={columns} dataSource={data.data?.items || []} loading={data.loading && !data.data} pagination={false} scroll={{ x: 1150 }} locale={{ emptyText: <NoData text={emptyText} /> }} /><div className="table-pagination"><span>{number(data.data?.total)} 条记录</span><Pagination size="small" current={page} pageSize={50} total={data.data?.total || 0} showSizeChanger={false} onChange={setPage} /></div></>
}
