import { useState } from 'react'
import { App, Button, Drawer, Input, Pagination, Select, Space, Table, Tabs, Tag, Tooltip, Typography } from 'antd'
import { DownloadOutlined } from '@ant-design/icons'
import { ApiClient, type LibraryRule } from './api'
import { LoadError, NoData, number, useLoad } from './ui'

export interface Upstream { source_id: string; revision: string; path: string; sha256: string }
export interface OriginalRule extends Omit<LibraryRule, 'engine'> {
  engine: string; upstream?: Upstream; capabilities?: string[]; default_disabled_reason?: string; runtime_reason?: string; execution_available?: boolean
}
export function saveBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}
export async function downloadSource(api: ApiClient, id: string) {
  saveBlob(`shen-${id}-upstream.zip`, await api.blob(`/library/sources/${encodeURIComponent(id)}/export`))
}
export function UpstreamCatalog({ api, open, close }: { api: ApiClient; open: boolean; close: () => void }) {
  const { message } = App.useApp()
  const [query, setQuery] = useState(''); const [purpose, setPurpose] = useState(''); const [page, setPage] = useState(1)
  const [selected, setSelected] = useState(''); const [busy, setBusy] = useState(false)
  const prefix = '/library/sources/nuclei-templates'
  const data = useLoad<{ items: OriginalRule[]; total: number; revision: string }>(api, open ? `${prefix}/catalog?${new URLSearchParams({ q: query, purpose, limit: '50', offset: String((page - 1) * 50) })}` : null)
  const detail = useLoad<OriginalRule>(api, selected ? `${prefix}/catalog/${encodeURIComponent(selected)}?revision=${encodeURIComponent(data.data?.revision || '')}` : null)
  const download = async () => { setBusy(true); try { await downloadSource(api, 'nuclei-templates') } catch (e) { message.error(e instanceof Error ? e.message : '下载失败') } finally { setBusy(false) } }
  const raw = async () => {
    if (!detail.data?.upstream) return
    try { const ref = detail.data.upstream; const blob = await api.blob(`${prefix}/files/raw?${new URLSearchParams({ revision: ref.revision, path: ref.path })}`); saveBlob(ref.path.split('/').pop() || 'template.yaml', blob) }
    catch (e) { message.error(e instanceof Error ? e.message : '下载失败') }
  }
  return <><Drawer title="Nuclei 上游原库" open={open} onClose={close} size={1180}>
    <div className="filter-bar"><Select aria-label="上游规则用途" value={purpose} onChange={v => { setPurpose(v); setPage(1) }} style={{ width: 145 }} options={[{ value: '', label: '全部用途' }, { value: 'discovery', label: '产品发现' }, { value: 'verification', label: '漏洞模板' }, { value: 'check', label: '其他检查' }]} /><Input.Search aria-label="搜索上游规则" placeholder="名称、ID、标签、产品" onSearch={v => { setQuery(v.trim()); setPage(1) }} allowClear className="result-search" /><span className="bar-spacer" /><Button icon={<DownloadOutlined />} loading={busy} disabled={!data.data?.revision} onClick={() => void download()}>下载原库 ZIP</Button></div>
    <div className="compact-note">此处为已同步的上游目录。需要执行的 HTTP 基础模板，请单独导入 PoC 库并关联指纹。</div>
    <LoadError error={data.error} retry={() => void data.reload()} />
    <Table<OriginalRule> rowKey="id" size="small" tableLayout="fixed" dataSource={data.data?.items || []} loading={data.loading && !data.data} pagination={false} scroll={{ x: 1000 }} locale={{ emptyText: <NoData text="请先完成 Nuclei 规则源更新" /> }} columns={[
      { title: '原始规则', key: 'name', width: 320, render: (_, rule) => <div className="name-cell"><button className="text-link strong" onClick={() => setSelected(rule.id)}>{rule.name}</button><Tooltip title={rule.id}><span className="cell-secondary mono line-clamp">{rule.id}</span></Tooltip></div> },
      { title: '用途 / 级别', key: 'kind', width: 150, render: (_, rule) => <Space size={3} wrap><Tag>{rule.purpose === 'discovery' ? '发现' : rule.purpose === 'verification' ? '漏洞' : '检查'}</Tag><Tag color={['critical', 'high'].includes(rule.severity) ? 'error' : rule.severity === 'medium' ? 'warning' : undefined}>{rule.severity}</Tag></Space> },
      { title: '关联产品', key: 'products', width: 160, render: (_, rule) => <Tooltip title={rule.applies_to?.join(' · ')}><span className="line-clamp">{rule.applies_to?.join(' · ') || '未声明'}</span></Tooltip> },
      { title: '来源路径', key: 'path', width: 240, render: (_, rule) => <Tooltip title={rule.upstream?.path}><span className="mono line-clamp">{rule.upstream?.path || '—'}</span></Tooltip> },
      { title: '状态', key: 'policy', width: 140, render: (_, rule) => <Tooltip title={rule.runtime_reason || '目录仅供查看、导出，不参与任务执行'}><Tag>已同步 · 仅目录</Tag></Tooltip> },
      { title: '', key: 'detail', width: 70, render: (_, rule) => <Button type="link" size="small" onClick={() => setSelected(rule.id)}>原文</Button> },
    ]} />
    <div className="table-pagination"><span>{number(data.data?.total)} 条原始规则 <span className="mono muted">{data.data?.revision.slice(0, 12)}</span></span><Pagination size="small" current={page} pageSize={50} total={data.data?.total || 0} showSizeChanger={false} onChange={setPage} /></div>
  </Drawer><Drawer title={detail.data?.name || '原始模板'} open={!!selected} onClose={() => setSelected('')} size={850} loading={detail.loading && !detail.data}>
    <LoadError error={detail.error} retry={() => void detail.reload()} />{detail.data && <><div className="rule-source-toolbar"><Typography.Text className="mono" copyable>{detail.data.nuclei?.template_id || detail.data.id}</Typography.Text><Button icon={<DownloadOutlined />} onClick={() => void raw()}>下载原文</Button></div><div className="compact-note mono">{detail.data.upstream?.path}</div><Space wrap>{detail.data.nuclei?.protocols?.map(value => <Tag key={value}>{value}</Tag>)}{detail.data.nuclei?.default_disabled_reason && <Tag color="warning">{detail.data.nuclei.default_disabled_reason}</Tag>}</Space><Tabs items={[{ key: 'yaml', label: 'YAML 原文', children: <Input.TextArea aria-label="上游 YAML 原文" className="mono rule-code" value={detail.data.template} readOnly rows={30} spellCheck={false} /> }, { key: 'metadata', label: '元信息', children: <pre className="evidence-block">{JSON.stringify({ upstream: detail.data.upstream, nuclei: detail.data.nuclei }, null, 2)}</pre> }]} /></>}
  </Drawer></>
}
