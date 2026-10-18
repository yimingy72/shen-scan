import { useState } from 'react'
import { Alert, App, Button, Collapse, Drawer, Space, Tag, Tooltip } from 'antd'
import { CloudDownloadOutlined } from '@ant-design/icons'
import { ApiClient, formatTime } from './api'
import { LoadError, number, useLoad } from './ui'
import { downloadSource, saveBlob } from './UpstreamCatalog'

export interface RuleSource {
  id: string; name: string; repository: string; license: string
  status: 'idle' | 'updating' | 'ready' | 'failed'; revision?: string; updated_at?: string; error?: string
  stats?: { bundle?: string; engine_revision?: string; validation?: Record<string, { total: number; loaded: number; excluded_active: number; excluded_unsupported: number; compile_failed: number }>; total: number; accepted: number; skipped: number; reasons: Record<string, number>; added: number; updated: number; unchanged: number; preserved: number; retired: number }
  samples?: { path: string; reason: string }[]
}
export interface RuleSourcesData { items: RuleSource[] }
const states = { idle: '尚未同步', updating: '同步中', ready: '已同步', failed: '更新失败' }

export function RuleSourcesDrawer({ api, open, close, data, loading, error, busy, refresh, update }: {
  api: ApiClient; open: boolean; close: () => void; data?: RuleSourcesData; loading: boolean; error: string; busy: string[]; refresh: () => void; update: (ids?: string[]) => Promise<void>
}) {
  const [detail, setDetail] = useState<string>()
  const [downloading, setDownloading] = useState('')
  const { message } = App.useApp()
  const download = async (id: string) => { setDownloading(id); try { await downloadSource(api, id) } catch (e) { message.error(e instanceof Error ? e.message : '下载失败') } finally { setDownloading('') } }
  const downloadBundle = async (digest: string) => {
    setDownloading(digest)
    try { saveBlob(`shen-fingers-${digest.slice(0, 12)}.json`, await api.blob(`/library/fingerprint-bundles/${encodeURIComponent(digest)}`)) }
    catch (e) { message.error(e instanceof Error ? e.message : '下载失败') } finally { setDownloading('') }
  }
  const [licenseSource, setLicenseSource] = useState<RuleSource>()
  const license = useLoad<{ license: string; license_text: string; revision: string }>(api, licenseSource ? `/library/sources/${encodeURIComponent(licenseSource.id)}/license` : null)
  const updating = busy.length > 0 || data?.items.some(source => source.status === 'updating')
  return <><Drawer title="开源规则库" open={open} onClose={close} size={780}>
    <div className="rule-source-toolbar"><span className="muted">新任务使用更新后的规则，已有任务保留快照。</span><Button type="primary" icon={<CloudDownloadOutlined />} loading={updating} disabled={!data?.items.length} onClick={() => void update()}>更新全部</Button></div>
    <LoadError error={error} retry={refresh} />
    {loading && !data && <div className="compact-note">正在加载规则源…</div>}
    <div className="rule-source-list">{data?.items.map(source => <section className="rule-source-card" key={source.id}>
      <div className="rule-source-heading"><div><h3>{source.id === 'fingers' ? 'HTTP 指纹合集（fingers）' : source.name}</h3><a href={source.repository} target="_blank" rel="noreferrer">{source.repository.replace('https://github.com/', '')}</a></div><span className="bar-spacer" /><Tag color={source.status === 'failed' ? 'error' : source.status === 'updating' ? 'processing' : source.status === 'ready' ? 'success' : undefined}>{states[source.status]}</Tag><Button size="small" loading={busy.includes(source.id) || source.status === 'updating'} onClick={() => void update([source.id])}>更新</Button></div>
      <div className="rule-source-version"><Button size="small" type="link" disabled={!source.revision} onClick={() => setLicenseSource(source)}>{source.id === 'fingers' ? '来源说明' : source.license || '许可证待校验'}</Button><Tooltip title={source.revision}><span className="mono">{source.revision?.slice(0, 12) || '—'}</span></Tooltip><span>最近检查 {formatTime(source.updated_at)}</span><Button size="small" type="link" loading={downloading === source.id} disabled={!source.revision} onClick={() => void download(source.id)}>下载原库 ZIP</Button>{source.id === 'fingers' && source.stats?.bundle && <Button size="small" type="link" loading={downloading === source.stats.bundle} onClick={() => void downloadBundle(source.stats!.bundle!)}>下载执行包</Button>}</div>
      {source.stats && (source.revision || source.stats.total > 0) && <><div className="rule-source-counts"><span>来源条目 <b>{number(source.stats.total)}</b></span><span>{source.id === 'fingers' ? '已加载' : '已收录'} <b>{number(source.stats.accepted)}</b></span><span>{source.id === 'fingers' ? '未加载' : '未索引'} <b>{number(source.stats.skipped)}</b></span></div><div className="rule-source-changes">{source.id === 'fingers' ? <>{Object.entries(source.stats.validation || {}).map(([key, value]) => <span key={key}>{{ fingers: 'Fingers', fingerprinthub: 'FingerprintHub', ehole: 'EHole', goby: 'Goby', aliases: '产品别名' }[key] || key} <b>{number(value.loaded)}</b> / {number(value.total)}</span>)}<Tooltip title={source.stats.bundle}><span className="mono">包 {source.stats.bundle?.slice(0, 12)}</span></Tooltip></> : <><span>新增 {number(source.stats.added)}</span><span>更新 {number(source.stats.updated)}</span><span>无变化 {number(source.stats.unchanged)}</span><span>保留本地 {number(source.stats.preserved)}</span><span>上游撤回 / 停用 {number(source.stats.retired)}</span></>}</div></>}
      {source.id === 'wappalyzer' && <div className="compact-note">新任务支持响应匹配与独立 JS / DOM 补充识别；不兼容规则在结果中列出。</div>}
      {source.status === 'updating' && <div className="source-progress">{source.id === 'fingers' ? '下载并校验完整 HTTP 规则及原生执行能力…' : '同步上游最新内容，原文与元信息整体发布。'}</div>}
      {source.error && <Alert type="error" title="本次更新失败，原规则库保留" description={source.error} showIcon />}
      {!!source.stats?.skipped && <Collapse size="small" ghost activeKey={detail === source.id ? ['details'] : []} onChange={keys => setDetail(keys.length ? source.id : undefined)} items={[{ key: 'details', label: source.id === 'fingers' ? '未加载原因与样例' : '未索引原因与样例', children: <><div className="rule-source-reasons">{Object.entries(source.stats.reasons || {}).sort((a, b) => b[1] - a[1]).map(([reason, count]) => <div key={reason}><span>{reason}</span><b>{number(count)}</b></div>)}</div>{!!source.samples?.length && <div className="rule-source-samples">{source.samples.map((item, index) => <div key={index}><span className="mono">{item.path}</span><span>{item.reason}</span></div>)}</div>}</> }]} />}
    </section>)}</div>
    <Space className="rule-source-footer"><Tag>上游最新原文</Tag><Tag>已有任务保持加载内容</Tag></Space>
  </Drawer><Drawer title={`${licenseSource?.name || '规则库'} · 许可证`} size={700} open={!!licenseSource} onClose={() => setLicenseSource(undefined)}><LoadError error={license.error} retry={() => void license.reload()} /><div className="compact-note mono">{license.data?.revision}</div><pre className="evidence-block">{license.data?.license_text || (license.loading ? '加载中…' : '暂无许可证记录')}</pre></Drawer></>
}
