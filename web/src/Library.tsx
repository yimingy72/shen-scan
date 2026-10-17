import { useEffect, useState } from 'react'
import { App, Button, Checkbox, Drawer, Form, Input, Pagination, Segmented, Select, Space, Switch, Table, Tag, Tooltip, Upload } from 'antd'
import { CopyOutlined, DownloadOutlined, ImportOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiClient, type LibraryRule, type RuleKind } from './api'
import { LoadError, NoData, Refresh, number, useLoad } from './ui'

export type LibraryPageData = { items: LibraryRule[]; total: number; counts: Record<RuleKind, number> }
const kindName: Record<RuleKind, string> = { http: 'HTTP 指纹', port: '端口指纹', poc: 'PoC 库' }
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
  useEffect(() => {
    if (!rule) return
    setError('')
    form.setFieldsValue({ id: existing?.id || `${kind}-custom-${crypto.randomUUID().slice(0, 8)}`, name: existing?.name || '', description: existing?.description || '', tags: existing?.tags || [], severity: existing?.severity || 'info', enabled: existing?.enabled || false, source: existing?.source || 'custom', content: engine === 'nuclei' ? existing?.template : JSON.stringify(existing?.definition || initialDefinition(kind), null, 2) })
  }, [rule, kind, form, existing, engine])
  const submit = async (values: Record<string, unknown>) => {
    setBusy(true); setError('')
    try {
      const body = { ...existing, id: String(values.id).trim(), kind: existing?.kind || kind, engine, name: String(values.name).trim(), description: values.description, severity: values.severity || existing?.severity || 'info', tags: values.tags || [], source: values.source, enabled: !!values.enabled, ...(engine === 'nuclei' ? { template: values.content } : { definition: JSON.parse(String(values.content)), template: '' }), ...(existing ? { expected_revision: existing.revision } : {}) }
      await api.request(existing ? `/library/${encodeURIComponent(existing.id)}` : '/library', { method: existing ? 'PUT' : 'POST', body: JSON.stringify(body) })
      saved(); close()
    } catch (e) { setError(e instanceof SyntaxError ? '规则 JSON 格式不正确' : e instanceof Error ? e.message : '保存失败') } finally { setBusy(false) }
  }
  return <Drawer title={existing ? existing.name : `新建${kindName[kind]}`} open={!!rule} onClose={close} size={720} destroyOnHidden>
    <LoadError error={error} />
    <Form form={form} layout="vertical" onFinish={submit} requiredMark={false} className="rule-form">
      <div className="two-fields"><Form.Item label="规则名称" name="name" rules={[{ required: true, whitespace: true, message: '请输入名称' }]}><Input maxLength={200} /></Form.Item><Form.Item label="规则 ID" name="id" rules={[{ required: true, message: '请输入规则 ID' }]}><Input className="mono" disabled={!!existing} /></Form.Item></div>
      <Form.Item label="描述" name="description"><Input.TextArea rows={2} maxLength={4096} /></Form.Item>
      <div className="two-fields"><Form.Item label="标签" name="tags"><Select mode="tags" tokenSeparators={[',']} placeholder="输入后回车" /></Form.Item><Form.Item label="来源" name="source"><Input maxLength={1024} /></Form.Item></div>
      {(existing?.kind || kind) === 'poc' && <div className="two-fields"><Form.Item label="风险级别" name="severity"><Select options={Object.entries(severityNames).map(([value, label]) => ({ value, label }))} /></Form.Item><div className="rule-engine-field"><span>执行引擎</span><Tag>{engine === 'nuclei' ? 'Nuclei' : '原生只读检查'}</Tag></div></div>}
      <Form.Item label={engine === 'nuclei' ? 'Nuclei 模板 · YAML' : '匹配定义 · JSON'} name="content" rules={[{ required: true, message: '请输入规则定义' }]}><Input.TextArea className="mono rule-code" rows={18} spellCheck={false} /></Form.Item>
      <div className="rule-editor-footer"><Form.Item name="enabled" valuePropName="checked" noStyle><Checkbox>启用规则</Checkbox></Form.Item>{existing && <span className="muted">{existing.builtin ? '内置' : '自定义'} · v{existing.revision}</span>}<span className="bar-spacer" /><Button onClick={close}>取消</Button><Button htmlType="submit" type="primary" loading={busy}>保存规则</Button></div>
    </Form>
  </Drawer>
}

function ImportRules({ api, open, close, imported }: { api: ApiClient; open: boolean; close: () => void; imported: () => void }) {
  const [format, setFormat] = useState('json')
  const [content, setContent] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const { message } = App.useApp()
  const submit = async () => {
    setBusy(true); setError('')
    try {
      const r = await api.request<{ count: number }>('/library/import', { method: 'POST', body: JSON.stringify({ format, content }) })
      message.success(`已导入 ${r.count} 条规则，默认禁用`); setContent(''); imported(); close()
    } catch (e) { setError(e instanceof Error ? e.message : '导入失败') } finally { setBusy(false) }
  }
  return <Drawer title="导入规则" open={open} onClose={close} size={720}><LoadError error={error} /><div className="import-toolbar"><Segmented value={format} onChange={setFormat} options={[{ label: '规则 JSON', value: 'json' }, { label: 'Nuclei YAML', value: 'nuclei' }]} /><span className="bar-spacer" /><Upload accept=".json,.yaml,.yml" showUploadList={false} beforeUpload={async file => { if (file.size > 1024 * 1024) { setError('文件不能超过 1 MB'); return false }; setContent(await file.text()); setFormat(/\.ya?ml$/i.test(file.name) ? 'nuclei' : 'json'); setError(''); return false }}><Button icon={<ImportOutlined />}>选择文件</Button></Upload></div><Input.TextArea rows={23} className="mono rule-code" aria-label="导入规则内容" value={content} onChange={e => setContent(e.target.value)} placeholder={format === 'json' ? '粘贴导出的规则 JSON' : '粘贴只读 HTTP GET / HEAD 模板'} spellCheck={false} /><div className="compact-note">导入后默认禁用。Nuclei 仅接受静态同源 GET / HEAD 与 word / regex / status 匹配器。</div><div className="drawer-actions"><Button onClick={close}>取消</Button><Button type="primary" loading={busy} disabled={!content.trim()} onClick={() => void submit()}>校验并导入</Button></div></Drawer>
}

export function LibraryPage({ api }: { api: ApiClient }) {
  const { message, modal } = App.useApp()
  const [kind, setKind] = useState<RuleKind>('http')
  const [query, setQuery] = useState('')
  const [enabled, setEnabled] = useState('')
  const [engine, setEngine] = useState('')
  const [page, setPage] = useState(1)
  const [editing, setEditing] = useState<LibraryRule | 'new' | null>(null)
  const [importOpen, setImportOpen] = useState(false)
  const [busyID, setBusyID] = useState('')
  const [exporting, setExporting] = useState(false)
  const path = '/library?' + new URLSearchParams({ kind, q: query, enabled, engine: kind === 'poc' ? engine : '', limit: '50', offset: String((page - 1) * 50) })
  const data = useLoad<LibraryPageData>(api, path)
  const load = async (id: string, copy = false) => {
    setBusyID(id)
    try {
      const r = await api.request<LibraryRule>(`/library/${encodeURIComponent(id)}`)
      if (copy) {
        const copyID = `${kind}-custom-${crypto.randomUUID().slice(0, 8)}`
        const item = { ...r, id: copyID, name: `${r.name}（副本）`, builtin: false, revision: 1, enabled: false, template: r.template?.replace(/^id:\s*.+$/m, `id: ${copyID}`) }
        await api.request('/library', { method: 'POST', body: JSON.stringify(item) }); void data.reload(); message.success('副本已创建，默认禁用')
      } else setEditing(r)
    } catch (e) { message.error(e instanceof Error ? e.message : '读取失败') } finally { setBusyID('') }
  }
  const toggle = async (rule: LibraryRule, value: boolean) => {
    setBusyID(rule.id)
    try { await api.request(`/library/${encodeURIComponent(rule.id)}`, { method: 'PATCH', body: JSON.stringify({ enabled: value, expected_revision: rule.revision }) }); await data.reload() }
    catch (e) { message.error(e instanceof Error ? e.message : '更新失败'); void data.reload() } finally { setBusyID('') }
  }
  const remove = (rule: LibraryRule) => modal.confirm({ title: `删除“${rule.name}”？`, content: '已有任务继续使用创建时的规则版本。', okText: '删除', cancelText: '返回', okButtonProps: { danger: true }, onOk: async () => { await api.request(`/library/${encodeURIComponent(rule.id)}?expected_revision=${rule.revision}`, { method: 'DELETE' }); void data.reload() } })
  const exportRules = async () => {
    setExporting(true)
    try { const r = await api.request<{ items: LibraryRule[] }>(`/library/export?kind=${kind}`); download(`shen-${kind}-rules.json`, r) }
    catch (e) { message.error(e instanceof Error ? e.message : '导出失败') } finally { setExporting(false) }
  }
  const columns = [
    { title: '规则名称', key: 'name', width: 280, render: (_: unknown, r: LibraryRule) => <div className="name-cell"><button className="text-link strong" onClick={() => void load(r.id)}>{r.name}</button><span className="cell-secondary mono">{r.id} · v{r.revision}</span></div> },
    { title: kind === 'poc' ? '请求范围' : '匹配规则', key: 'definition', width: 320, render: (_: unknown, r: LibraryRule) => <Tooltip title={r.match_summary || r.description}><span className="line-clamp mono">{r.match_summary || r.description || '—'}</span></Tooltip> },
    ...(kind === 'poc' ? [{ title: '引擎 / 级别', key: 'engine', width: 155, render: (_: unknown, r: LibraryRule) => <Space size={4}><Tag>{r.engine === 'nuclei' ? 'Nuclei' : '原生'}</Tag><Severity value={r.severity} /></Space> }] : []),
    { title: '标签', key: 'tags', width: 175, render: (_: unknown, r: LibraryRule) => <span className="tag-list">{r.tags?.slice(0, 3).map(t => <Tag key={t}>{t}</Tag>)}</span> },
    { title: '来源', key: 'source', width: 80, render: (_: unknown, r: LibraryRule) => <Tooltip title={r.source}><Tag>{r.builtin ? '内置' : '自定义'}</Tag></Tooltip> },
    { title: '启用', key: 'enabled', width: 65, render: (_: unknown, r: LibraryRule) => <Switch size="small" aria-label={`启用 ${r.name}`} checked={r.enabled} loading={busyID === r.id} onChange={v => void toggle(r, v)} /> },
    { title: '', key: 'actions', width: 145, render: (_: unknown, r: LibraryRule) => <Space size={2}><Button type="link" size="small" onClick={() => void load(r.id)}>编辑</Button><Tooltip title="复制为自定义规则"><Button type="text" size="small" aria-label={`复制 ${r.name}`} icon={<CopyOutlined />} onClick={() => void load(r.id, true)} /></Tooltip>{!r.builtin && <Button type="link" danger size="small" onClick={() => void remove(r)}>删除</Button>}</Space> },
  ]
  return <><div className="page-bar"><h1>指纹库</h1><div className="page-tabs" role="tablist" aria-label="规则库分类">{(['http', 'port', 'poc'] as const).map(k => <button key={k} role="tab" aria-selected={kind === k} onClick={() => { setKind(k); setPage(1); setQuery(''); setEngine('') }}>{kindName[k]} <span className="count-badge">{number(data.data?.counts?.[k])}</span></button>)}</div><span className="bar-spacer" /><Refresh onClick={() => void data.reload()} loading={data.loading} /><Button icon={<ImportOutlined />} onClick={() => setImportOpen(true)}>导入</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing('new')}>新建规则</Button></div><LoadError error={data.error} retry={() => void data.reload()} /><section className="table-panel"><div className="filter-bar"><Select aria-label="规则状态" value={enabled} onChange={v => { setEnabled(v); setPage(1) }} options={[{ value: '', label: '全部状态' }, { value: 'true', label: '已启用' }, { value: 'false', label: '已禁用' }]} style={{ width: 125 }} />{kind === 'poc' && <Select aria-label="PoC 引擎" value={engine} onChange={v => { setEngine(v); setPage(1) }} options={[{ value: '', label: '全部引擎' }, { value: 'native', label: '原生检查' }, { value: 'nuclei', label: 'Nuclei' }]} style={{ width: 130 }} />}<Input.Search key={kind} className="result-search" aria-label="搜索规则" placeholder="搜索名称、ID 或标签" allowClear onSearch={v => { setQuery(v.trim()); setPage(1) }} /><Button type="text" icon={<DownloadOutlined />} loading={exporting} onClick={() => void exportRules()}>导出</Button></div><Table rowKey="id" size="small" tableLayout="fixed" dataSource={data.data?.items || []} columns={columns} loading={data.loading && !data.data} pagination={false} scroll={{ x: kind === 'poc' ? 1220 : 1040 }} locale={{ emptyText: <NoData text="没有符合条件的规则" /> }} /><div className="table-pagination"><span>{number(data.data?.total)} 条规则</span><Pagination size="small" current={page} pageSize={50} total={data.data?.total || 0} showSizeChanger={false} onChange={setPage} /></div></section><RuleEditor api={api} rule={editing} kind={kind} close={() => setEditing(null)} saved={() => { void data.reload(); message.success('规则已保存') }} /><ImportRules api={api} open={importOpen} close={() => setImportOpen(false)} imported={() => void data.reload()} /></>
}
