import { useEffect, useRef, useState } from 'react'
import { App, Button, Checkbox, Drawer, Form, Input, Pagination, Segmented, Select, Space, Switch, Table, Tag, Tooltip, Upload } from 'antd'
import { CloudDownloadOutlined, CopyOutlined, DeleteOutlined, DownloadOutlined, ImportOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiClient, type LibraryRule, type RuleKind } from './api'
import { LoadError, NoData, Refresh, number, useLoad } from './ui'
import { RuleSourcesDrawer, type RuleSourcesData } from './RuleSources'
import { UpstreamCatalog } from './UpstreamCatalog'

export type LibraryPageData = { items: LibraryRule[]; total: number; counts: Record<RuleKind, number>; purpose_counts?: Record<string, number> }
const kindName: Record<RuleKind, string> = { http: 'HTTP 指纹', port: '端口指纹', poc: 'PoC 库' }
export function RulePurpose({ value }: { value?: string }) { return <Tag color={value === 'verification' ? 'volcano' : undefined}>{value === 'verification' ? '漏洞验证' : value === 'check' ? '其他检查' : '发现检查'}</Tag> }
export const severityNames: Record<string, string> = { info: '信息', low: '低危', medium: '中危', high: '高危', critical: '严重' }
export function Severity({ value }: { value?: string }) {
  return <Tag color={value === 'critical' || value === 'high' ? 'error' : value === 'medium' ? 'warning' : value === 'low' ? 'processing' : undefined}>{severityNames[value || 'info'] || value}</Tag>
}
function initialDefinition(kind: RuleKind) {
  if (kind === 'poc') return { condition: 'and', requests: [{ method: 'GET', path: '/', condition: 'and', matchers: [{ part: 'status', type: 'status', status: [200] }, { part: 'body', type: 'word', words: ['replace-with-exact-evidence'] }] }] }
  return { product: 'Example', condition: 'and', matchers: [{ part: kind === 'port' ? 'banner' : 'header', type: 'word', words: [kind === 'port' ? 'Example service' : 'Server: Example'] }] }
}
function download(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
  const link = document.createElement('a'); link.href = url; link.download = name; link.click(); URL.revokeObjectURL(url)
}

function RuleEditor({ api, rule, kind, close, saved }: { api: ApiClient; rule: LibraryRule | 'new' | null; kind: RuleKind; close: () => void; saved: () => void }) {
  const [form] = Form.useForm()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const existing = rule && rule !== 'new' ? rule : undefined
  const engine = existing?.engine || 'native'
  const verification = existing?.verification
  const products = useLoad<{ items: string[] }>(api, rule && (existing?.kind || kind) === 'poc' ? '/library/products' : null)
  useEffect(() => {
    if (!rule) return
    setError('')
    form.setFieldsValue({ id: existing?.id || `${kind}-custom-${crypto.randomUUID().slice(0, 8)}`, name: existing?.name || '', description: existing?.description || '', tags: existing?.tags || [], applies_to: existing?.applies_to || [], severity: existing?.severity || 'info', enabled: existing?.enabled || false, source: existing?.source || 'custom', content: engine === 'nuclei' ? existing?.template : JSON.stringify(engine === 'httpx-cff' ? existing?.fingerprint || {} : existing?.definition || initialDefinition(kind), null, 2) })
  }, [rule, kind, form, existing, engine])
  const submit = async (values: Record<string, unknown>) => {
    setBusy(true); setError('')
    try {
      const body = { ...existing, id: String(values.id).trim(), kind: existing?.kind || kind, engine, name: String(values.name).trim(), description: values.description, severity: values.severity || existing?.severity || 'info', tags: values.tags || [], applies_to: (existing?.kind || kind) === 'poc' ? values.applies_to || [] : [], source: values.source, enabled: !!values.enabled, ...(engine === 'nuclei' ? { template: values.content } : engine === 'httpx-cff' ? { fingerprint: JSON.parse(String(values.content)), definition: existing?.definition || {}, template: '' } : { definition: JSON.parse(String(values.content)), template: '' }), ...(existing ? { expected_revision: existing.revision } : {}) }
      await api.request(existing ? `/library/${encodeURIComponent(existing.id)}` : '/library', { method: existing ? 'PUT' : 'POST', body: JSON.stringify(body) })
      saved(); close()
    } catch (e) { setError(e instanceof SyntaxError ? '规则 JSON 格式不正确' : e instanceof Error ? e.message : '保存失败') } finally { setBusy(false) }
  }
  return <Drawer title={existing ? existing.name : `新建${kindName[kind]}`} open={!!rule} onClose={close} size={720} destroyOnHidden>
    <LoadError error={error} />
    {verification && <div className="verification-note"><Space wrap><RulePurpose value="verification" />{verification.cves.map(cve => <Tag key={cve}>{cve}</Tag>)}<Tag>正向验证 + 阴性对照</Tag></Space><p>{verification.summary}</p><a href={`${verification.source_pin.repository}/blob/${verification.source_pin.revision}/${verification.source_pin.path}`} target="_blank" rel="noreferrer">官方模板 · {verification.source_pin.revision.slice(0, 12)}</a></div>}
    <Form form={form} layout="vertical" onFinish={submit} requiredMark={false} className="rule-form">
      <div className="two-fields"><Form.Item label="规则名称" name="name" rules={[{ required: true, whitespace: true, message: '请输入名称' }]}><Input maxLength={200} /></Form.Item><Form.Item label="规则 ID" name="id" rules={[{ required: true, message: '请输入规则 ID' }]}><Input className="mono" disabled={!!existing} /></Form.Item></div>
      <Form.Item label="描述" name="description"><Input.TextArea rows={2} maxLength={4096} /></Form.Item>
      <div className="two-fields"><Form.Item label="标签" name="tags"><Select disabled={!!verification} mode="tags" tokenSeparators={[',']} placeholder="输入后回车" /></Form.Item><Form.Item label="来源" name="source"><Input readOnly={!!verification} maxLength={1024} /></Form.Item></div>
      {(existing?.kind || kind) === 'poc' && <div className="two-fields"><Form.Item label="风险级别" name="severity"><Select disabled={!!verification} options={Object.entries(severityNames).map(([value, label]) => ({ value, label }))} /></Form.Item><div className="rule-engine-field"><span>执行引擎</span><Tag>{engine === 'nuclei' ? 'Nuclei' : '原生只读检查'}</Tag></div></div>}
      {(existing?.kind || kind) === 'poc' && <><Form.Item label="关联指纹" name="applies_to" extra="匹配任一组件后执行；留空则需在任务中手动选择该规则。"><Select disabled={!!verification} mode="tags" tokenSeparators={[',']} aria-label="关联指纹" placeholder="例如 WordPress、Apache Tomcat" loading={products.loading} options={products.data?.items.map(value => ({ value, label: value })) || []} /></Form.Item><LoadError error={products.error} retry={() => void products.reload()} /></>}
      {existing?.nuclei?.execution_profile === 'http-basic-v1' && <div className="compact-note mono">原始 YAML · {existing.nuclei?.template_id} · SHA-256 {existing.nuclei?.content_sha256?.slice(0, 16)}…</div>}
      <Form.Item label={engine === 'nuclei' ? 'Nuclei 模板 · YAML' : engine === 'httpx-cff' ? 'Wappalyzer 原始规则 · JSON' : '匹配定义 · JSON'} name="content" rules={[{ required: true, message: '请输入规则定义' }]}><Input.TextArea readOnly={!!verification} className="mono rule-code" rows={18} spellCheck={false} /></Form.Item>
      <div className="rule-editor-footer"><Form.Item name="enabled" valuePropName="checked" noStyle><Checkbox>启用规则</Checkbox></Form.Item>{existing && <span className="muted">{existing.builtin ? '内置' : '自定义'} · v{existing.revision}</span>}<span className="bar-spacer" /><Button onClick={close}>取消</Button><Button htmlType="submit" type="primary" loading={busy}>保存规则</Button></div>
    </Form>
  </Drawer>
}

function ImportRules({ api, open, close, imported }: { api: ApiClient; open: boolean; close: () => void; imported: () => void }) {
  const [format, setFormat] = useState('json')
  const [profile, setProfile] = useState('http-basic-v1')
  const [content, setContent] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const { message } = App.useApp()
  const submit = async () => {
    setBusy(true); setError('')
    try {
      const body = JSON.stringify({ format, content, ...(format === 'nuclei' ? { execution_profile: profile } : {}) })
      if (new Blob([body]).size > 32 * 1024 * 1024) throw new Error('导入请求不能超过 32 MB，请分批导入')
      const r = await api.request<{ count: number }>('/library/import', { method: 'POST', body })
      message.success(`已导入 ${r.count} 条规则，默认禁用`); setContent(''); imported(); close()
    } catch (e) { setError(e instanceof Error ? e.message : '导入失败') } finally { setBusy(false) }
  }
  return <Drawer title="导入规则" open={open} onClose={close} size={720}><LoadError error={error} /><div className="import-toolbar"><Segmented value={format} onChange={setFormat} options={[{ label: '规则 JSON', value: 'json' }, { label: 'Nuclei YAML', value: 'nuclei' }]} /><span className="bar-spacer" /><Upload accept=".json,.yaml,.yml" showUploadList={false} beforeUpload={async file => { if (file.size > 32 * 1024 * 1024) { setError('文件不能超过 32 MB'); return false }; setContent(await file.text()); setFormat(/\.ya?ml$/i.test(file.name) ? 'nuclei' : 'json'); setError(''); return false }}><Button icon={<ImportOutlined />}>选择文件</Button></Upload></div>{format === 'nuclei' && <div className="filter-bar" style={{ paddingTop: 10 }}><span className="muted">执行格式</span><Segmented size="small" value={profile} onChange={value => setProfile(String(value))} options={[{ label: '原始 YAML（受支持子集）', value: 'http-basic-v1' }, { label: '兼容规范化（旧）', value: 'legacy' }]} /></div>}<Input.TextArea rows={23} className="mono rule-code" aria-label="导入规则内容" value={content} onChange={e => setContent(e.target.value)} placeholder={format === 'json' ? '粘贴导出的规则 JSON，最多 10000 条' : profile === 'http-basic-v1' ? '原始 Nuclei YAML：GET / HEAD，最多 3 个静态请求，需明确 info.metadata.product' : '粘贴旧版可规范化模板'} spellCheck={false} /><div className="compact-note">导入后默认禁用。原始 YAML 保留注释与原始模板 ID；仅支持静态同源只读请求，执行前按识别到的产品精确匹配。</div><div className="drawer-actions"><Button onClick={close}>取消</Button><Button type="primary" loading={busy} disabled={!content.trim()} onClick={() => void submit()}>校验并导入</Button></div></Drawer>
}

export function LibraryPage({ api, active = true }: { api: ApiClient; active?: boolean }) {
  const { message, modal } = App.useApp()
  const [kind, setKind] = useState<RuleKind>('http')
  const [query, setQuery] = useState('')
  const [sourceID, setSourceID] = useState('')
  const [purpose, setPurpose] = useState('')
  const [enabled, setEnabled] = useState('')
  const [engine, setEngine] = useState('')
  const [page, setPage] = useState(1)
  const [editing, setEditing] = useState<LibraryRule | 'new' | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [busyID, setBusyID] = useState('')
  const [exporting, setExporting] = useState(false)
  const [selected, setSelected] = useState<LibraryRule[]>([])
  const [sourcesOpen, setSourcesOpen] = useState(false)
  const [catalogOpen, setCatalogOpen] = useState(false)
  const [sourcePolling, setSourcePolling] = useState(false)
  const [sourceBusy, setSourceBusy] = useState<string[]>([])
  useEffect(() => { if (!active) { setEditing(null); setImportOpen(false); setSourcesOpen(false); setCatalogOpen(false) } }, [active])
  const sources = useLoad<RuleSourcesData>(api, '/library/sources', sourcePolling ? 3000 : 0)
  const passiveSource = sources.data?.items.find(source => source.id === 'fingers')
  const passiveCount = Object.entries(passiveSource?.stats?.validation || {}).filter(([key]) => key !== 'aliases').reduce((sum, [, value]) => sum + value.loaded, 0)
  const sourceVersions = useRef<string | undefined>(undefined)
  const path = '/library?' + new URLSearchParams({ kind, q: query, enabled, source_id: sourceID, purpose: kind === 'poc' ? purpose : '', engine: kind === 'poc' ? engine : '', limit: '50', offset: String((page - 1) * 50) })
  const data = useLoad<LibraryPageData>(api, path)
  useEffect(() => { setSelected([]) }, [kind, query, enabled, engine, sourceID, purpose])
  const reload = () => { setSelected([]); void data.reload() }
  useEffect(() => {
    if (!sources.data) return
    setSourcePolling(sources.data.items.some(source => source.status === 'updating'))
    const signature = sources.data.items.map(source => `${source.id}:${source.revision || ''}:${source.updated_at || ''}`).join('|')
    if (sourceVersions.current !== undefined && sourceVersions.current !== signature) { setSelected([]); void data.reload() }
    sourceVersions.current = signature
  }, [sources.data, data.reload])
  const updateSources = async (ids?: string[]) => {
    const selectedIDs = ids || sources.data?.items.map(source => source.id) || []
    if (!selectedIDs.length) return
    setSourcesOpen(true); setSourceBusy(previous => [...new Set([...previous, ...selectedIDs])]); setSourcePolling(true)
    const results = await Promise.allSettled(selectedIDs.map(id => api.request(`/library/sources/${encodeURIComponent(id)}/update`, { method: 'POST' })))
    const failed = results.filter(result => result.status === 'rejected') as PromiseRejectedResult[]
    if (failed.length) message.error(failed.map(result => result.reason instanceof Error ? result.reason.message : '无法启动更新').join('；'))
    setSourceBusy(previous => previous.filter(id => !selectedIDs.includes(id))); await sources.reload()
  }
  const load = async (id: string, copy = false) => {
    setBusyID(id)
    try {
      const r = await api.request<LibraryRule>(`/library/${encodeURIComponent(id)}`)
      if (copy) {
        const copyID = `${kind}-custom-${crypto.randomUUID().slice(0, 8)}`
        const item = { ...r, id: copyID, name: `${r.name}（副本）`, builtin: false, revision: 1, enabled: false, template: r.nuclei?.execution_profile === 'http-basic-v1' ? r.template : r.template?.replace(/^id:\s*.+$/m, `id: ${copyID}`) }
        await api.request('/library', { method: 'POST', body: JSON.stringify(item) }); reload(); message.success('副本已创建，默认禁用')
      } else setEditing(r)
    } catch (e) { message.error(e instanceof Error ? e.message : '读取失败') } finally { setBusyID('') }
  }
  const toggle = async (rule: LibraryRule, value: boolean) => {
    setBusyID(rule.id)
    try { await api.request(`/library/${encodeURIComponent(rule.id)}`, { method: 'PATCH', body: JSON.stringify({ enabled: value, expected_revision: rule.revision }) }); setSelected([]); await data.reload() }
    catch (e) { message.error(e instanceof Error ? e.message : '更新失败'); void data.reload() } finally { setBusyID('') }
  }
  const remove = (rules: LibraryRule[]) => modal.confirm({ title: rules.length === 1 ? `删除“${rules[0].name}”？` : `删除选中的 ${number(rules.length)} 条规则？`, content: '删除后不再用于新任务，重启不会恢复；已有任务保留原规则快照。', okText: '删除', cancelText: '返回', okButtonProps: { danger: true }, onOk: async () => {
    try { await api.request('/library/delete', { method: 'POST', body: JSON.stringify({ items: rules.map(r => ({ id: r.id, expected_revision: r.revision })) }) }); reload(); message.success(`已删除 ${number(rules.length)} 条规则`) }
    catch (e) { message.error(e instanceof Error ? e.message : '删除失败'); void data.reload(); throw e }
  } })
  const exportRules = async (onlySelected = false) => {
    setExporting(true)
    try { const params = new URLSearchParams(onlySelected ? { kind, ids: selected.map(r => r.id).join(',') } : { kind, q: query, enabled, source_id: sourceID, purpose: kind === 'poc' ? purpose : '', engine: kind === 'poc' ? engine : '' }); const r = await api.request<{ items: LibraryRule[] }>(`/library/export?${params}`); download(`shen-${kind}-rules${onlySelected ? '-selected' : ''}.json`, r) }
    catch (e) { message.error(e instanceof Error ? e.message : '导出失败') } finally { setExporting(false) }
  }
  const columns = [
    { title: '规则名称', key: 'name', width: kind === 'poc' ? 240 : 280, render: (_: unknown, r: LibraryRule) => <div className="name-cell"><button className="text-link strong" onClick={() => void load(r.id)}>{r.name}</button><Tooltip title={r.id}>{kind === 'poc' && <span><RulePurpose value={r.purpose} /></span>}<span className="cell-secondary mono">{r.id.length > 34 ? `${r.id.slice(0, 31)}…` : r.id} · v{r.revision}</span></Tooltip></div> },
    ...(kind === 'poc' ? [{ title: '关联指纹', key: 'products', width: 180, render: (_: unknown, r: LibraryRule) => r.applies_to?.length ? <Tooltip title={r.applies_to.join(' · ')}><span className="tag-list">{r.applies_to.slice(0, 2).map(p => <Tag key={p}>{p}</Tag>)}{r.applies_to.length > 2 && <Tag>+{r.applies_to.length - 2}</Tag>}</span></Tooltip> : <Tag>手动指定</Tag> }] : []),
    { title: kind === 'poc' ? '请求范围' : '匹配规则', key: 'definition', width: kind === 'poc' ? 235 : 320, render: (_: unknown, r: LibraryRule) => <Tooltip title={r.match_summary || r.description}><span className="line-clamp mono">{r.match_summary || r.description || '—'}</span></Tooltip> },
    ...(kind === 'poc' ? [{ title: '引擎 / 级别', key: 'engine', width: 165, render: (_: unknown, r: LibraryRule) => <Space size={4}><Tooltip title={r.nuclei?.execution_profile === 'http-basic-v1' ? `原始 YAML · ${r.nuclei?.template_id}` : undefined}><Tag color={r.nuclei?.execution_profile === 'http-basic-v1' ? 'geekblue' : undefined}>{r.engine === 'nuclei' ? (r.nuclei?.execution_profile === 'http-basic-v1' ? 'Nuclei 原文' : 'Nuclei') : '原生'}</Tag></Tooltip><Severity value={r.severity} /></Space> }] : []),
    ...(kind !== 'poc' ? [{ title: '标签', key: 'tags', width: 175, render: (_: unknown, r: LibraryRule) => <span className="tag-list">{r.tags?.slice(0, 3).map(t => <Tag key={t}>{t}</Tag>)}</span> }] : []),
    { title: '来源', key: 'source', width: 105, render: (_: unknown, r: LibraryRule) => <Tooltip title={r.source}><Tag>{r.source_id === 'wappalyzer' ? 'Wappalyzer' : r.source_id === 'nuclei-templates' ? 'Nuclei' : r.builtin ? '内置' : '自定义'}</Tag></Tooltip> },
    { title: '启用', key: 'enabled', width: 65, render: (_: unknown, r: LibraryRule) => <Switch size="small" aria-label={`启用 ${r.name}`} checked={r.enabled} loading={busyID === r.id} onChange={v => void toggle(r, v)} /> },
    { title: '', key: 'actions', width: 145, render: (_: unknown, r: LibraryRule) => <Space size={2}><Button type="link" size="small" onClick={() => void load(r.id)}>编辑</Button><Tooltip title="复制为自定义规则"><Button disabled={r.purpose === 'verification'} type="text" size="small" aria-label={`复制 ${r.name}`} icon={<CopyOutlined />} onClick={() => void load(r.id, true)} /></Tooltip><Button type="link" danger size="small" onClick={() => void remove([r])}>删除</Button></Space> },
  ]
  return <>
    <div className="page-bar"><h1>指纹库</h1><div className="page-tabs" role="tablist" aria-label="规则库分类">{(['http', 'port', 'poc'] as const).map(k => <button key={k} role="tab" aria-selected={kind === k} onClick={() => { setKind(k); setPage(1); setQuery(''); setEngine(''); setSourceID(''); setPurpose(k === 'poc' ? 'verification' : '') }}>{kindName[k]} <span className="count-badge">{number(data.data?.counts?.[k])}</span></button>)}</div><span className="bar-spacer" /><Refresh onClick={reload} loading={data.loading} /><Button type="primary" icon={<CloudDownloadOutlined />} loading={sourceBusy.length > 0 || sourcePolling} disabled={!sources.data?.items.length} onClick={() => void updateSources()}>一键更新</Button>{kind === 'http' && <Button onClick={() => setSourcesOpen(true)}>被动库 · {passiveSource?.stats?.bundle ? number(passiveCount) : '内置'}</Button>}<Button onClick={() => setCatalogOpen(true)}>上游原库</Button><Button onClick={() => setSourcesOpen(true)}>更新记录</Button><Button icon={<ImportOutlined />} onClick={() => setImportOpen(true)}>导入</Button><Button icon={<PlusOutlined />} onClick={() => setEditing('new')}>新建规则</Button></div>
    <LoadError error={data.error} retry={reload} />
    <section className="table-panel">
      <div className="filter-bar"><Select aria-label="规则状态" value={enabled} onChange={v => { setEnabled(v); setPage(1) }} options={[{ value: '', label: '全部状态' }, { value: 'true', label: '已启用' }, { value: 'false', label: '已禁用' }]} style={{ width: 125 }} />{kind !== 'port' && <Select aria-label="规则来源" value={sourceID} onChange={value => { setSourceID(value); setPage(1) }} style={{ width: 145 }} options={[{ value: '', label: '全部来源' }, ...(sources.data?.items.filter(source => kind === 'http' ? source.id === 'wappalyzer' : source.id === 'nuclei-templates').map(source => ({ value: source.id, label: source.name })) || [])]} />}{kind === 'poc' && <Select aria-label="检查类型" value={purpose} onChange={value => { setPurpose(value); setPage(1) }} style={{ width: 145 }} options={[{ value: '', label: '全部检查' }, { value: 'verification', label: `漏洞验证 ${number(data.data?.purpose_counts?.verification)}` }, { value: 'discovery', label: `发现检查 ${number(data.data?.purpose_counts?.discovery)}` }, { value: 'check', label: `其他检查 ${number(data.data?.purpose_counts?.check)}` }]} />}{kind === 'poc' && <Select aria-label="PoC 引擎" value={engine} onChange={v => { setEngine(v); setPage(1) }} options={[{ value: '', label: '全部引擎' }, { value: 'native', label: '原生检查' }, { value: 'nuclei', label: 'Nuclei' }]} style={{ width: 130 }} />}<Input.Search key={kind} className="result-search" aria-label="搜索规则" placeholder="搜索名称、ID、标签或关联指纹" allowClear onSearch={v => { setQuery(v.trim()); setPage(1) }} /><Button type="text" icon={<DownloadOutlined />} loading={exporting} onClick={() => void exportRules()}>导出筛选结果</Button></div>
      {!!selected.length && <div className="library-selection"><span>已选 <b>{number(selected.length)}</b> 条</span><Button size="small" type="text" onClick={() => setSelected([])}>清空选择</Button><span className="bar-spacer" /><Button size="small" icon={<DownloadOutlined />} loading={exporting} onClick={() => void exportRules(true)}>导出选中</Button><Button size="small" danger icon={<DeleteOutlined />} onClick={() => remove(selected)}>删除选中</Button></div>}
      <Table rowKey="id" size="small" tableLayout="fixed" rowSelection={{ selectedRowKeys: selected.map(r => r.id), preserveSelectedRowKeys: true, onChange: (_, rows) => setSelected(rows.filter(Boolean).slice(0, 1000)), getCheckboxProps: r => ({ disabled: selected.length >= 1000 && !selected.some(x => x.id === r.id), 'aria-label': `选择 ${r.name}` }) }} dataSource={data.data?.items || []} columns={columns} loading={data.loading && !data.data} pagination={false} scroll={{ x: kind === 'poc' ? 1220 : 1120 }} locale={{ emptyText: <NoData text="没有符合条件的规则" /> }} />
      <div className="table-pagination"><span>{number(data.data?.total)} 条规则</span><Pagination size="small" current={page} pageSize={50} total={data.data?.total || 0} showSizeChanger={false} onChange={setPage} /></div>
    </section>
    <UpstreamCatalog api={api} open={catalogOpen} close={() => setCatalogOpen(false)} />
    <RuleSourcesDrawer api={api} open={sourcesOpen} close={() => setSourcesOpen(false)} data={sources.data} loading={sources.loading} error={sources.error} busy={sourceBusy} refresh={() => void sources.reload()} update={updateSources} />
    <RuleEditor api={api} rule={editing} kind={kind} close={() => setEditing(null)} saved={() => { reload(); message.success('规则已保存') }} /><ImportRules api={api} open={importOpen} close={() => setImportOpen(false)} imported={reload} />
  </>
}
