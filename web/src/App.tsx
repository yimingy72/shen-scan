import { useEffect, useMemo, useState } from 'react'
import { App as AntApp, Button, Checkbox, Drawer, Form, Input, Segmented, Space, Table, Tag, Tooltip, Upload } from 'antd'
import { ArrowRightOutlined, CloudServerOutlined, DatabaseOutlined, FileSearchOutlined, ImportOutlined, LogoutOutlined, PlusOutlined, SafetyOutlined, SearchOutlined } from '@ant-design/icons'
import { ApiClient, type Run, formatTime } from './api'
import { Brand, LoadError, NoData, Refresh, Status, number, shortTime, useLoad } from './ui'
import { ResultsPage } from './Results'
import { WorkersPage } from './Workers'

const AUTH_KEY = 'scan-platform-connection'
type Connection = { base: string; token: string }
type Route = { page: 'runs' | 'results' | 'workers'; runId: string }
function readConnection(): Connection | null {
  try { const c = JSON.parse(sessionStorage.getItem(AUTH_KEY) || 'null'); return c && typeof c.base === 'string' && typeof c.token === 'string' ? c : null } catch { return null }
}
function readRoute(): Route {
  const [path, query] = location.hash.slice(1).split('?')
  return { page: path === 'results' || path === 'workers' ? path : 'runs', runId: new URLSearchParams(query).get('run') || '' }
}
function go(page: Route['page'], runId = '') { location.hash = page + (runId ? `?run=${encodeURIComponent(runId)}` : '') }

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

function CreateRun({ open, api, close, created }: { open: boolean; api: ApiClient; close: () => void; created: (run: Run) => void }) {
  const [form] = Form.useForm<{ name: string; targets: string; modes: string[] }>()
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const text = Form.useWatch('targets', form) || ''
  const targets = parseTargets(text)
  const domainCount = targets.filter(item => !/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(item)).length
  const modes = Form.useWatch('modes', form) || []
  const submit = async (values: { name: string; targets: string; modes: string[] }) => {
    setSaving(true); setError('')
    try {
      const result = await api.request<Run>('/runs', { method: 'POST', body: JSON.stringify({ name: values.name.trim(), targets: parseTargets(values.targets), modes: values.modes }) })
      form.resetFields(); created(result)
    } catch (reason) { setError(reason instanceof Error ? reason.message : '创建任务失败') } finally { setSaving(false) }
  }
  const importFile = async (file: File) => {
    if (file.size > 4 * 1024 * 1024) { setError('文件不能超过 4 MB'); return false }
    try { form.setFieldValue('targets', await file.text()); setError('') } catch { setError('读取文件失败') }
    return false
  }
  return <Drawer title="新建扫描任务" open={open} onClose={close} size={480} destroyOnHidden><LoadError error={error} /><Form form={form} layout="vertical" onFinish={submit} initialValues={{ modes: ['port', 'http'] }} requiredMark={false}><Form.Item name="name" label="任务名称" rules={[{ required: true, whitespace: true, message: '请输入任务名称' }]}><Input maxLength={120} placeholder="例如：生产环境巡检" /></Form.Item><div className="field-heading"><span>扫描目标</span><Upload accept=".txt,.csv" showUploadList={false} beforeUpload={importFile}><Button type="text" size="small" icon={<ImportOutlined />}>导入 TXT / CSV</Button></Upload></div><Form.Item name="targets" rules={[{ required: true, whitespace: true, message: '请输入扫描目标' }]}><Input.TextArea className="mono" rows={8} placeholder={'192.0.2.10\n192.0.2.0/24\nexample.com\nhttps://example.com:8443/'} /></Form.Item><div className="form-summary">{targets.length ? `${number(targets.length)} 条输入 · ${number(domainCount)} 个域名 / URL` : '支持 IP、CIDR、域名和 URL，每行一个'}</div><Form.Item name="modes" label="扫描模式" rules={[{ required: true, message: '请选择至少一种扫描模式' }]}><Checkbox.Group className="mode-options"><Checkbox value="port"><strong>端口扫描</strong><span>TCP 1–65535 · 包含服务指纹</span></Checkbox><Checkbox value="http"><strong>HTTP 指纹</strong><span>包含 CMS / 框架识别</span></Checkbox></Checkbox.Group></Form.Item>{domainCount > 0 && <div className={modes.includes('http') ? 'form-summary' : 'form-validation'}>{modes.includes('http') ? '域名仅执行 HTTP 指纹识别' : '输入包含域名 / URL，请选择 HTTP 指纹'}</div>}<div className="drawer-actions"><Button onClick={close}>取消</Button><Button type="primary" htmlType="submit" loading={saving} disabled={domainCount > 0 && !modes.includes('http')}>创建任务</Button></div></Form></Drawer>
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

function RunsPage({ runs, loading, reload, openCreate }: { runs: Run[]; loading: boolean; reload: () => void; openCreate: () => void }) {
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
    { title: '', key: 'actions', width: 65, render: (_: unknown, run: Run) => <Button type="link" size="small" onClick={() => go('results', run.id)}>结果</Button> },
  ]
  return <><div className="page-bar"><h1>扫描任务</h1><span className="count-badge">{number(runs.length)}</span><span className="bar-spacer" /><Refresh onClick={reload} loading={loading} /><Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新建任务</Button></div><section className="table-panel"><div className="filter-bar"><Segmented value={filter} onChange={setFilter} options={[{ label: '全部', value: 'all' }, { label: `未结束 ${runs.filter(r => ['pending', 'running', 'paused'].includes(r.status)).length}`, value: 'active' }, { label: '已结束', value: 'ended' }]} /><Input prefix={<SearchOutlined />} aria-label="搜索任务" placeholder="搜索任务名称" allowClear value={query} onChange={e => setQuery(e.target.value)} className="search-input" /></div><Table size="small" rowKey="id" columns={columns} dataSource={visible} loading={loading && !runs.length} pagination={{ defaultPageSize: 50, showSizeChanger: true, pageSizeOptions: [20, 50, 100], showTotal: total => `${total} 个任务` }} scroll={{ x: 1060 }} locale={{ emptyText: <NoData text="还没有扫描任务" /> }} /></section></>
}

function Workspace({ connection, logout }: { connection: Connection; logout: () => void }) {
  const api = useMemo(() => new ApiClient(connection.base, connection.token), [connection])
  const [route, setRoute] = useState<Route>(readRoute)
  const [createOpen, setCreateOpen] = useState(false)
  const [runPoll, setRunPoll] = useState(10000)
  const runsData = useLoad<{ items: Run[] }>(api, route.page === 'workers' ? null : '/runs?summary=true', runPoll)
  const runs = runsData.data?.items || []
  useEffect(() => {
    if (runsData.data) setRunPoll(runsData.data.items.some(r => ['pending', 'running', 'paused'].includes(r.status)) ? 10000 : 60000)
  }, [runsData.data])
  useEffect(() => { const listener = () => setRoute(readRoute()); window.addEventListener('hashchange', listener); return () => window.removeEventListener('hashchange', listener) }, [])
  return <div className="app-shell"><aside className="sidebar"><Brand /><nav aria-label="主导航">{[{ key: 'runs', label: '扫描任务', icon: <FileSearchOutlined /> }, { key: 'results', label: '扫描结果', icon: <DatabaseOutlined /> }, { key: 'workers', label: 'Workers', icon: <CloudServerOutlined /> }].map(item => <button key={item.key} className={`nav-item ${route.page === item.key ? 'active' : ''}`} onClick={() => go(item.key as Route['page'], item.key === 'results' ? route.runId : '')} aria-current={route.page === item.key ? 'page' : undefined} aria-label={item.label}>{item.icon}<span>{item.label}</span></button>)}</nav><div className="sidebar-footer"><Status value={runsData.error ? 'offline' : 'ready'} label={runsData.error ? '连接异常' : '控制面在线'} /><a className="scanner-source" href="/downloads/masscan-source-1.3.2-scan-platform.tar.gz">扫描器源码 · AGPLv3</a><button className="user-button" onClick={logout}><span className="avatar">AD</span><span>管理员</span><LogoutOutlined /></button></div></aside><main className="workspace"><LoadError error={runsData.error} retry={() => void runsData.reload()} />{route.page === 'runs' && <RunsPage runs={runs} loading={runsData.loading} reload={() => void runsData.reload()} openCreate={() => setCreateOpen(true)} />}{route.page === 'results' && <ResultsPage api={api} runs={runs} runId={route.runId} selectRun={id => go('results', id)} reloadRuns={() => void runsData.reload()} />}{route.page === 'workers' && <WorkersPage api={api} openRun={id => go('results', id)} />}</main><CreateRun api={api} open={createOpen} close={() => setCreateOpen(false)} created={run => { setCreateOpen(false); void runsData.reload(); go('results', run.id) }} /></div>
}

export default function App() {
  const [connection, setConnection] = useState<Connection | null>(readConnection)
  return <AntApp>{connection ? <Workspace connection={connection} logout={() => { sessionStorage.removeItem(AUTH_KEY); setConnection(null) }} /> : <Login onConnected={setConnection} />}</AntApp>
}
