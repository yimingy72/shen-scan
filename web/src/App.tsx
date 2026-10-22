import { lazy, memo, Suspense, startTransition, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { App as AntApp, Button, Checkbox, Drawer, Form, Input, Segmented, Select, Space, Table, Tag, Tooltip, Upload } from 'antd'
import { ArrowRightOutlined, CloudServerOutlined, DatabaseOutlined, FileSearchOutlined, ImportOutlined, LogoutOutlined, PlusOutlined, SafetyOutlined, SearchOutlined, BookOutlined } from '@ant-design/icons'
import { ApiClient, type Run, type WebScanOptions, formatTime } from './api'
import { Brand, LoadError, NoData, PageActivity, Refresh, Status, clearLoadCache, number, shortTime, useLoad } from './ui'
import type { LibraryPageData } from './Library'
import { TaskTools } from './TaskTools'

const ResultsPage = memo(lazy(() => import('./Results').then(module => ({ default: module.ResultsPage }))), (previous, next) => {
  if (previous.active || next.active) return previous.api === next.api && previous.runs === next.runs && previous.runId === next.runId && previous.active === next.active && previous.selectRun === next.selectRun && previous.reloadRuns === next.reloadRuns && previous.copyRun === next.copyRun && previous.deletedRun === next.deletedRun
  return previous.api === next.api && previous.runId === next.runId && previous.active === next.active && previous.copyRun === next.copyRun && previous.deletedRun === next.deletedRun
})
function prefetchPage(page: Route['page']) {
  if (page === 'results') void import('./Results')
  else if (page === 'workers') void import('./Workers')
  else if (page === 'library') void import('./Library')
}
const WorkersPage = memo(lazy(() => import('./Workers').then(module => ({ default: module.WorkersPage }))))
const LibraryPage = memo(lazy(() => import('./Library').then(module => ({ default: module.LibraryPage }))))

const AUTH_KEY = 'scan-platform-connection'
const LAST_RUN_KEY = 'scan-platform-last-run'
type Connection = { base: string; token: string }
type Route = { page: 'runs' | 'results' | 'workers' | 'library'; runId: string }
function readConnection(): Connection | null {
  try { const c = JSON.parse(sessionStorage.getItem(AUTH_KEY) || 'null'); return c && typeof c.base === 'string' && typeof c.token === 'string' ? c : null } catch { return null }
}
function readRoute(): Route {
  const [path, query] = location.hash.slice(1).split('?')
  return { page: path === 'results' || path === 'workers' || path === 'library' ? path : 'runs', runId: new URLSearchParams(query).get('run') || '' }
}
const pageScroll = new Map<Route['page'], number>()
function go(page: Route['page'], runId = '') {
  pageScroll.set(readRoute().page, window.scrollY)
  location.hash = page + (runId ? `?run=${encodeURIComponent(runId)}` : '')
}
function PageSlot({ active, children }: { active: boolean; children: ReactNode }) {
  return <div className="page-slot" hidden={!active}>{children}</div>
}

function Login({ onConnected }: { onConnected: (connection: Connection) => void }) {
  const [checking, setChecking] = useState(false)
  const [error, setError] = useState('')
  const connect = async (values: Connection) => {
    const connection = { base: (values.base || '/api').trim().replace(/\/$/, ''), token: values.token.trim() }
    setChecking(true); setError('')
    try { await new ApiClient(connection.base, connection.token).request('/worker-pool'); sessionStorage.setItem(AUTH_KEY, JSON.stringify(connection)); onConnected(connection) }
    catch (reason) { setError(reason instanceof Error ? reason.message : '登录失败') } finally { setChecking(false) }
  }
  return <main className="login-shell"><section className="login-identity"><Brand /><div><h1>发现端口。<br />看清服务。</h1><p>TCP 全端口 / 服务指纹 / HTTP 指纹</p><div className="login-grid" aria-hidden="true">{Array.from({ length: 30 }, (_, i) => <span key={i} />)}</div></div><span className="login-caption">ASSET DISCOVERY</span></section><section className="login-main"><div className="login-form"><div className="mobile-brand"><Brand /></div><h2>登录工作台</h2><p className="muted">扫描平台</p><LoadError error={error === 'invalid administrator token' ? '访问令牌不正确' : error} /><Form layout="vertical" initialValues={{ base: '/api' }} onFinish={connect} requiredMark={false}><Form.Item label="访问令牌" name="token" rules={[{ required: true, whitespace: true, message: '请输入管理员令牌' }]}><Input.Password autoComplete="current-password" placeholder="输入管理员令牌" size="large" /></Form.Item><Button type="primary" block size="large" htmlType="submit" loading={checking}>登录 <ArrowRightOutlined /></Button><details className="connection-settings"><summary>连接设置</summary><Form.Item label="API 地址" name="base"><Input placeholder="/api" /></Form.Item></details></Form><span className="login-session"><SafetyOutlined /> 当前浏览器会话</span></div></section></main>
}

export function parseTargets(text: string) {
  const ignored = new Set(['target', 'targets', 'ip', 'domain', 'url', '目标'])
  return [...new Set(text.split(/[\r\n,;\t]+/).map(item => item.trim().replace(/^['"]|['"]$/g, '')).filter(item => item && !ignored.has(item.toLowerCase())))]
}

type CreateRunValues = { name: string; targets: string; modes: string[]; poc_enabled: boolean; poc_rule_ids: string[]; web_scan_options: WebScanOptions }

function CreateRun({ open, api, close, created, source }: { open: boolean; api: ApiClient; close: () => void; created: (run: Run) => void; source?: Run }) {
  const [form] = Form.useForm<CreateRunValues>()
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const text = Form.useWatch('targets', form) || ''
  const targets = parseTargets(text)
  const domainCount = targets.filter(item => !/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(item)).length
  const modes = Form.useWatch('modes', form) || []
  const pocEnabled = !!Form.useWatch('poc_enabled', form)
  const [pocSearch, setPocSearch] = useState('')
  const [pocQuery, setPocQuery] = useState('')
  useEffect(() => { const timer = window.setTimeout(() => setPocQuery(pocSearch.trim()), 250); return () => clearTimeout(timer) }, [pocSearch])
  const pocRules = useLoad<LibraryPageData>(api, open ? `/library?kind=poc&enabled=true&limit=200&q=${encodeURIComponent(pocQuery)}` : null)
  const submit = async (values: CreateRunValues) => {
    setSaving(true); setError('')
    try {
      const result = await api.request<Run>('/runs', { method: 'POST', body: JSON.stringify({ name: values.name.trim(), targets: parseTargets(values.targets), modes: values.modes, ...(values.modes.includes('http') ? { web_scan_options: values.web_scan_options } : {}), poc_enabled: !!values.poc_enabled, poc_rule_ids: values.poc_enabled ? values.poc_rule_ids || [] : [] }) })
      form.resetFields(); created(result)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '创建任务失败') } finally { setSaving(false) }
  }
  const importFile = async (file: File) => {
    if (file.size > 4 * 1024 * 1024) { setError('文件不能超过 4 MB'); return false }
    try { form.setFieldValue('targets', await file.text()); setError('') } catch { setError('读取文件失败') }
    return false
  }
  return <Drawer title={source ? "复制为新任务" : "新建扫描任务"} open={open} onClose={close} size={480} destroyOnHidden><LoadError error={error} /><Form form={form} layout="vertical" onFinish={submit} initialValues={{ name: source ? `${source.name} · 复扫`.slice(0, 120) : '', targets: source?.targets.join('\n') || '', modes: source?.modes || ['port', 'http'], poc_enabled: false, poc_rule_ids: [], web_scan_options: source?.web_scan_options || { passive: true, active: true, js_dom: false, screenshot: false } }} onValuesChange={changed => { if (changed.modes && !changed.modes.includes('http')) form.setFieldsValue({ poc_enabled: false, poc_rule_ids: [] }) }} requiredMark={false}>{source && <div className="compact-note">复制自 {source.name} · 新任务使用当前规则，请核对扫描方式。</div>}<Form.Item name="name" label="任务名称" rules={[{ required: true, whitespace: true, message: '请输入任务名称' }]}><Input maxLength={120} placeholder="例如：生产环境巡检" /></Form.Item><div className="field-heading"><span>扫描目标</span><Upload accept=".txt,.csv" showUploadList={false} beforeUpload={importFile}><Button type="text" size="small" icon={<ImportOutlined />}>导入 TXT / CSV</Button></Upload></div><Form.Item name="targets" rules={[{ required: true, whitespace: true, message: '请输入扫描目标' }]}><Input.TextArea className="mono" rows={6} placeholder={'192.0.2.10\n192.0.2.0/24\nexample.com\nhttps://example.com:8443/'} /></Form.Item><div className="form-summary">{targets.length ? `${number(targets.length)} 条输入 · ${number(domainCount)} 个域名 / URL` : '支持 IP、CIDR、域名和 URL，每行一个'}</div><Form.Item name="modes" label="扫描模式" rules={[{ required: true, message: '请选择至少一种扫描模式' }]}><Checkbox.Group className="mode-options"><Checkbox value="port"><strong>端口扫描</strong><span>TCP 1–65535 · 包含服务指纹</span></Checkbox><Checkbox value="http"><strong>HTTP 指纹</strong><span>包含 CMS / 框架识别</span></Checkbox></Checkbox.Group></Form.Item>{modes.includes('http') && <div className="web-scan-options"><div className="field-heading"><span>HTTP 扫描方式</span><span className="muted">基础采集始终执行</span></div><div className="web-scan-grid">{([
    ['passive', '被动指纹', '匹配响应头、HTML 和图标'],
    ['active', '主动指纹', '按规则请求特定路径'],
    ['js_dom', 'JS / DOM', '浏览器运行时识别'],
    ['screenshot', '首页截图', '在结果列表预览页面'],
  ] as const).map(([key, label, hint]) => <Form.Item key={key} name={['web_scan_options', key]} valuePropName="checked" noStyle><Checkbox><strong>{label}</strong><span>{hint}</span></Checkbox></Form.Item>)}</div></div>}<div className="poc-choice"><Form.Item name="poc_enabled" valuePropName="checked" noStyle><Checkbox disabled={!modes.includes('http')}>PoC / Nuclei · 只读验证</Checkbox></Form.Item>{pocEnabled && <><LoadError error={pocRules.error} retry={() => void pocRules.reload()} /><Form.Item name="poc_rule_ids" noStyle><Select mode="multiple" aria-label="选择 PoC 规则" placeholder="按已识别指纹自动匹配" filterOption={false} onSearch={setPocSearch} loading={pocRules.loading} maxTagCount={3} optionFilterProp="label" options={pocRules.data?.items.map(r => ({ value: r.id, label: `${r.purpose === 'verification' ? '验证' : '发现'} · ${r.name}${r.applies_to?.length ? ` · ${r.applies_to.join(' / ')}` : ' · 手动指定'}${r.engine === 'nuclei' ? ' · Nuclei' : ''}` })) || []} /></Form.Item><div className="form-summary">按指纹匹配；漏洞验证与发现检查分别记录</div></>}</div>{domainCount > 0 && <div className={modes.includes('http') ? 'form-summary' : 'form-validation'}>{modes.includes('http') ? '域名仅执行 HTTP 指纹识别' : '输入包含域名 / URL，请选择 HTTP 指纹'}</div>}<div className="drawer-actions"><Button onClick={close}>取消</Button><Button type="primary" htmlType="submit" loading={saving} disabled={(domainCount > 0 && !modes.includes('http')) || (pocEnabled && (!!pocRules.error || pocRules.loading))}>创建任务</Button></div></Form></Drawer>
}

export function RunActions({ api, run, changed }: { api: ApiClient; run: Run; changed: () => void }) {
  const { message, modal } = AntApp.useApp()
  const [busy, setBusy] = useState(false)
  const act = async (action: string) => {
    setBusy(true)
    try { await api.request(`/runs/${run.id}/${action}`, { method: 'POST' }); changed(); message.success(action === 'cancel' ? '任务已取消' : action === 'pause' ? '任务已暂停' : '任务已恢复') } catch (e) { message.error(e instanceof Error ? e.message : '操作失败') } finally { setBusy(false) }
  }
  return <Space size={6}>{['running', 'pending'].includes(run.status) && <Button size="small" disabled={busy} onClick={() => void act('pause')}>暂停</Button>}{run.status === 'paused' && <Button type="primary" size="small" disabled={busy} onClick={() => void act('resume')}>恢复</Button>}{['running', 'pending', 'paused'].includes(run.status) && <Button size="small" danger disabled={busy} onClick={() => modal.confirm({ title: '取消这个扫描任务？', content: '停止后续扫描，已收到的结果会保留。', okText: '取消任务', cancelText: '返回', okButtonProps: { danger: true }, onOk: () => act('cancel') })}>取消任务</Button>}</Space>
}

function RunsPage({ api, runs, loading, reload, openCreate, copyRun, deletedRun }: { api: ApiClient; runs: Run[]; loading: boolean; reload: () => void; openCreate: () => void; copyRun: (id: string) => void; deletedRun: (id: string) => void }) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const visible = runs.filter(run => `${run.name} ${run.id}`.toLowerCase().includes(query.toLowerCase()) && (filter === 'all' || (filter === 'active' ? ['pending', 'running', 'paused'].includes(run.status) : ['completed', 'cancelled', 'partial', 'failed'].includes(run.status))))
  const columns = [
    { title: '任务名称', key: 'name', width: 245, render: (_: unknown, run: Run) => <div className="name-cell"><button className="text-link strong" onClick={() => go('results', run.id)}>{run.name}</button><span className="cell-secondary mono">{run.targets.slice(0, 2).join(' · ')}{(run.input_count ?? run.targets.length) > 2 && ` +${(run.input_count ?? run.targets.length) - 2}`}</span></div> },
    { title: '状态', dataIndex: 'status', width: 95, render: (status: string) => <Status value={status} /> },
    { title: '模式', dataIndex: 'modes', width: 130, render: (modes: string[]) => <span className="tag-list">{modes.map(mode => <Tag key={mode}>{mode === 'port' ? '端口 + 服务' : 'HTTP'}</Tag>)}</span> },
    { title: '目标', dataIndex: 'target_count', width: 70, align: 'right' as const, render: number },
    { title: '开放端口', dataIndex: 'open_port_count', width: 85, align: 'right' as const, render: number },
    { title: 'HTTP 端点', dataIndex: 'http_count', width: 90, align: 'right' as const, render: number },
    { title: '目标进度', key: 'progress', width: 135, render: (_: unknown, r: Run) => <div><div className="step-progress"><span>{number(r.target_done)} / {number(r.target_count)}</span><span className="progress-track"><i style={{ width: `${r.target_count ? (r.target_done / r.target_count) * 100 : 0}%` }} /></span></div>{r.task_failed > 0 && <span className="cell-secondary error-text">{r.task_failed} 步失败</span>}</div> },
    { title: '创建时间', dataIndex: 'created_at', width: 125, render: (time: string) => <Tooltip title={formatTime(time)}><span className="muted">{shortTime(time)}</span></Tooltip> },
    { title: '', key: 'actions', width: 110, render: (_: unknown, run: Run) => <Space size={0}><Button type="link" size="small" onClick={() => go('results', run.id)}>结果</Button><TaskTools api={api} run={run} copy={copyRun} deleted={deletedRun} compact /></Space> },
  ]
  return <><div className="page-bar"><h1>扫描任务</h1><span className="count-badge">{number(runs.length)}</span><span className="bar-spacer" /><Refresh onClick={reload} loading={loading} /><Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建任务</Button></div><section className="table-panel"><div className="filter-bar"><Segmented value={filter} onChange={setFilter} options={[{ label: '全部', value: 'all' }, { label: `未结束 ${runs.filter(r => ['pending', 'running', 'paused'].includes(r.status)).length}`, value: 'active' }, { label: '已结束', value: 'ended' }]} /><Input prefix={<SearchOutlined />} aria-label="搜索任务" placeholder="搜索任务名称" allowClear value={query} onChange={e => setQuery(e.target.value)} className="search-input" /></div><Table size="small" rowKey="id" columns={columns} dataSource={visible} loading={loading && !runs.length} pagination={{ defaultPageSize: 50, showSizeChanger: true, pageSizeOptions: [20, 50, 100], showTotal: total => `${total} 个任务` }} scroll={{ x: 1060 }} locale={{ emptyText: <NoData text="还没有扫描任务" /> }} /></section></>
}

function Workspace({ connection, logout }: { connection: Connection; logout: () => void }) {
  const { message } = AntApp.useApp()
  const api = useMemo(() => new ApiClient(connection.base, connection.token), [connection])
  const [route, setRoute] = useState<Route>(readRoute)
  const [mounted, setMounted] = useState<Set<Route['page']>>(() => new Set([route.page]))
  const currentPage = useRef(route.page)
  const lastRunId = useRef(route.runId || sessionStorage.getItem(LAST_RUN_KEY) || '')
  const [createOpen, setCreateOpen] = useState(false)
  const [createSource, setCreateSource] = useState<Run>()
  const [createKey, setCreateKey] = useState(0)
  const [deletedIDs, setDeletedIDs] = useState<Set<string>>(() => new Set())
  const [runPoll, setRunPoll] = useState(10000)
  const runsData = useLoad<{ items: Run[] }>(api, ['workers', 'library'].includes(route.page) ? null : '/runs?summary=true', runPoll)
  const loadedRuns = useMemo(() => (runsData.data?.items || []).filter(run => !deletedIDs.has(run.id)), [runsData.data, deletedIDs])
  const lastRuns = useRef<Run[]>([])
  if (runsData.data) lastRuns.current = loadedRuns
  const runs = runsData.data ? loadedRuns : lastRuns.current
  useEffect(() => {
    if (runsData.data) setRunPoll(runsData.data.items.some(r => ['pending', 'running', 'paused'].includes(r.status)) ? 10000 : 60000)
  }, [runsData.data])
  useEffect(() => {
    setMounted(previous => previous.has(route.page) ? previous : new Set(previous).add(route.page))
  }, [route.page])
  useEffect(() => { currentPage.current = route.page }, [route.page])
  useEffect(() => {
    if (route.page === 'results' && route.runId) {
      lastRunId.current = route.runId
      sessionStorage.setItem(LAST_RUN_KEY, route.runId)
    }
  }, [route.page, route.runId])
  useEffect(() => {
    const listener = () => {
      const next = readRoute()
      if (next.page !== currentPage.current) pageScroll.set(currentPage.current, window.scrollY)
      startTransition(() => setRoute(next))
    }
    window.addEventListener('hashchange', listener)
    return () => window.removeEventListener('hashchange', listener)
  }, [])
  useLayoutEffect(() => { window.scrollTo(0, pageScroll.get(route.page) ?? 0) }, [route.page])
  const reloadRuns = useCallback(() => void runsData.reload(), [runsData.reload])
  const selectRun = useCallback((id: string) => go('results', id), [])
  const openCreate = useCallback(() => { setCreateSource(undefined); setCreateKey(n => n + 1); setCreateOpen(true) }, [])
  const copyRun = useCallback(async (id: string) => {
    try {
      const source = await api.request<Run>(`/runs/${encodeURIComponent(id)}`)
      setCreateSource(source); setCreateKey(n => n + 1); setCreateOpen(true)
    } catch (e) { message.error(e instanceof Error ? e.message : '无法读取原任务') }
  }, [api, message])
  const deletedRun = useCallback((id: string) => {
    clearLoadCache()
    setDeletedIDs(ids => new Set(ids).add(id))
    lastRuns.current = lastRuns.current.filter(run => run.id !== id)
    if (lastRunId.current === id) { lastRunId.current = ''; sessionStorage.removeItem(LAST_RUN_KEY) }
    if (readRoute().runId === id) go('runs')
    reloadRuns()
  }, [reloadRuns])
  const pageActive = (page: Route['page']) => route.page === page

  return <div className="app-shell">
    <aside className="sidebar">
      <Brand />
      <nav aria-label="主导航">
        {[{ key: 'runs', label: '扫描任务', icon: <FileSearchOutlined /> }, { key: 'results', label: '扫描结果', icon: <DatabaseOutlined /> }, { key: 'workers', label: 'Workers', icon: <CloudServerOutlined /> }, { key: 'library', label: '指纹库', icon: <BookOutlined /> }].map(item =>
          <button key={item.key} className={`nav-item ${route.page === item.key ? 'active' : ''}`} onClick={() => go(item.key as Route['page'], item.key === 'results' ? (route.runId || lastRunId.current) : '')} onMouseEnter={() => prefetchPage(item.key as Route['page'])} onFocus={() => prefetchPage(item.key as Route['page'])} aria-current={route.page === item.key ? 'page' : undefined} aria-label={item.label}>{item.icon}<span>{item.label}</span></button>
        )}
      </nav>
      <div className="sidebar-footer">
        <Status value={runsData.error ? 'offline' : 'ready'} label={runsData.error ? '连接异常' : '控制面在线'} />
        <a className="scanner-source" href="/downloads/masscan-source-1.3.2-scan-platform.tar.gz">扫描器源码 · AGPLv3</a>
        <button className="user-button" onClick={logout}><span className="avatar">AD</span><span>管理员</span><LogoutOutlined /></button>
      </div>
    </aside>
    <main className="workspace">
      <LoadError error={runsData.error} retry={reloadRuns} />
      {mounted.has('runs') && <PageSlot active={pageActive('runs')}>
        <PageActivity active={pageActive('runs')}>
          <RunsPage api={api} runs={runs} loading={runsData.loading} reload={reloadRuns} openCreate={openCreate} copyRun={copyRun} deletedRun={deletedRun} />
        </PageActivity>
      </PageSlot>}
      {mounted.has('results') && <PageSlot active={pageActive('results')}>
        <PageActivity active={pageActive('results')}>
          <Suspense fallback={<div className="page-loading">正在载入扫描结果…</div>}>
            <ResultsPage api={api} runs={runs} runId={route.runId || lastRunId.current} selectRun={selectRun} reloadRuns={reloadRuns} copyRun={copyRun} deletedRun={deletedRun} active={pageActive('results')} />
          </Suspense>
        </PageActivity>
      </PageSlot>}
      {mounted.has('workers') && <PageSlot active={pageActive('workers')}>
        <PageActivity active={pageActive('workers')}>
          <Suspense fallback={<div className="page-loading">正在载入 Workers…</div>}>
            <WorkersPage api={api} openRun={selectRun} active={pageActive('workers')} />
          </Suspense>
        </PageActivity>
      </PageSlot>}
      {mounted.has('library') && <PageSlot active={pageActive('library')}>
        <PageActivity active={pageActive('library')}>
          <Suspense fallback={<div className="page-loading">正在载入指纹库…</div>}>
            <LibraryPage api={api} active={pageActive('library')} />
          </Suspense>
        </PageActivity>
      </PageSlot>}
    </main>
    <CreateRun key={createKey} api={api} source={createSource} open={createOpen} close={() => setCreateOpen(false)} created={run => { setCreateOpen(false); void runsData.reload(); go('results', run.id) }} />
  </div>
}

export default function App() {
  const [connection, setConnection] = useState<Connection | null>(readConnection)
  return <AntApp>{connection ? <Workspace connection={connection} logout={() => { clearLoadCache(); sessionStorage.removeItem(AUTH_KEY); sessionStorage.removeItem(LAST_RUN_KEY); setConnection(null) }} /> : <Login onConnected={setConnection} />}</AntApp>
}
