import { useEffect, useMemo, useState } from 'react'
import { Alert, App as AntApp, Button, Descriptions, Drawer, Form, Input, InputNumber, Segmented, Space, Table, Tabs, Tag, Tooltip, Typography } from 'antd'
import { CloudOutlined, CloudServerOutlined, PlayCircleOutlined, SearchOutlined, StopOutlined } from '@ant-design/icons'
import { ApiClient, type CloudConfig, type CloudInstance, type Pool, type Worker, formatTime } from './api'
import { LoadError, NoData, Refresh, Status, number, relativeTime, useLoad } from './ui'
import { SchedulerPanel } from './Scheduler'

type Node = { id: string; name: string; status: string; worker?: Worker; cloud?: CloudInstance; zone: string; type: string; cores: number; memory: number; reason: string }
function combineNodes(workers: Worker[], instances: CloudInstance[]) {
  const byID = new Map<string, Node>()
  const build = (id: string, w?: Worker, c?: CloudInstance): Node => {
    const reason = String(w?.spec?.drain_reason || c?.details.drain_reason || c?.details.reconcile_error || '')
    let status = c?.released ? 'released' : c?.state === 'Unknown' ? 'unknown' : w?.status || 'starting'
    if (!c?.released && (w?.status === 'draining' || c?.drain_started)) status = /interruption|recycling/i.test(reason) ? 'interruption' : 'draining'
    else if (status === 'running' || status === 'ready') status = w?.active_tasks?.length ? 'busy' : 'ready'
    return { id, name: w?.hostname || id, worker: w, cloud: c, status, zone: w?.az || String(c?.details.zone_id || ''), type: String(w?.spec?.instance_type || c?.details.instance_type || ''), cores: Number(w?.spec?.cpu_cores || c?.details.cpu_cores || 0), memory: Number(w?.spec?.memory_mib || c?.details.memory_mib || 0), reason }
  }
  for (const c of instances) byID.set(c.instance_id, build(c.instance_id, workers.find(w => w.instance_id === c.instance_id), c))
  for (const w of workers) if (!byID.has(w.instance_id)) byID.set(w.instance_id, build(w.instance_id, w))
  const rank = ['interruption', 'unknown', 'offline', 'draining', 'starting', 'busy', 'ready', 'released']
  return [...byID.values()].sort((a, b) => rank.indexOf(a.status) - rank.indexOf(b.status) || a.name.localeCompare(b.name))
}

function CloudSettings({ api, config, pool, active, tab, reload }: { api: ApiClient; config: CloudConfig; pool?: Pool; active: boolean; tab: string; reload: () => Promise<void> }) {
  const { message, modal } = AntApp.useApp()
  const [form] = Form.useForm()
  const [busy, setBusy] = useState('')
  const [error, setError] = useState('')
  const [verified, setVerified] = useState<{ verified_at: string; account_id: string }>()
  const blocked = !!pool?.enabled || active
  const account = config.account
  const initial = { name: account.name || '阿里云账号', region: account.region || 'cn-hangzhou', zone: account.zone || 'cn-hangzhou-h' }
  const request = (values: Record<string, unknown>) => ({ ...initial, ...values, expected_revision: account.revision })
  const verify = async () => {
    setBusy('verify'); setError('')
    try { const result = await api.request<{ verified_at: string; account_id: string }>('/cloud/aliyun/verify', { method: 'POST', body: JSON.stringify(request(form.getFieldsValue())) }); setVerified(result); message.success('账号身份及 ECS、VPC、系统事件查询验证通过') }
    catch (e) { setError(e instanceof Error ? e.message : '连接验证失败') } finally { setBusy('') }
  }
  const save = async (values: Record<string, unknown>) => {
    setBusy('save'); setError('')
    try { const result = await api.request<{ network_reset: boolean }>('/cloud/aliyun', { method: 'PUT', body: JSON.stringify(request(values)) }); form.resetFields(['access_key_id', 'access_key_secret', 'security_token']); setVerified(undefined); await reload(); message.success(result.network_reset ? '配置已保存，请重新准备云网络' : '阿里云配置已验证并保存') }
    catch (e) { setError(e instanceof Error ? e.message : '保存失败') } finally { setBusy('') }
  }
  const submit = (values: Record<string, unknown>) => {
    if (tab === 'resources' && (values.region !== account.region || values.zone !== account.zone)) modal.confirm({ title: '更换地域或可用区？', content: '当前网络绑定将重置，原云资源不会自动删除。保存后需要重新准备云网络。', okText: '验证并保存', cancelText: '返回', onOk: () => save(values) })
    else void save(values)
  }
  const setup = async () => {
    setBusy('setup'); setError('')
    try { await api.request('/worker-pool/setup-cloud', { method: 'POST', signal: AbortSignal.timeout(150000) }); await reload(); message.success('VPC、交换机与安全组已就绪') }
    catch (e) { setError(e instanceof Error ? e.message : '准备网络失败') } finally { setBusy('') }
  }
  return <div className="settings-layout"><section className="settings-panel"><div className="settings-heading"><span className="cloud-mark"><CloudOutlined /></span><div><h2>{tab === 'account' ? '阿里云账号' : '地域与云网络'}</h2><span className="muted">{tab === 'account' ? config.access_key_masked : account.name}</span></div><span className="bar-spacer" /><Status value={verified || account.verified_at ? 'ready' : config.has_credentials ? 'pending' : 'unknown'} label={verified || account.verified_at ? '已验证' : config.has_credentials ? '待验证' : '未配置'} /></div><LoadError error={error} />{blocked && <Alert className="inline-alert" type="info" showIcon title="停止 Worker 池并等待实例释放后，可修改配置。" />}<Form form={form} layout="vertical" initialValues={initial} requiredMark={false} onFinish={submit}>{tab === 'account' ? <><Form.Item label="账号名称" name="name" rules={[{ required: true, whitespace: true, message: '请输入账号名称' }]}><Input maxLength={60} disabled={blocked} /></Form.Item><Form.Item label="AccessKey ID" name="access_key_id" rules={[{ required: !config.has_credentials, message: '请输入 AccessKey ID' }]}><Input autoComplete="off" placeholder={config.has_credentials ? `${config.access_key_masked} · 留空则不修改` : '输入 AccessKey ID'} disabled={blocked} /></Form.Item><Form.Item label="AccessKey Secret" name="access_key_secret" rules={[{ required: !config.has_credentials, message: '请输入 AccessKey Secret' }]}><Input.Password autoComplete="new-password" placeholder={config.has_credentials ? '已保存，留空则不修改' : '输入 AccessKey Secret'} disabled={blocked} /></Form.Item><details className="advanced-settings"><summary>临时凭据（STS）</summary><Form.Item label="Security Token" name="security_token"><Input.Password autoComplete="new-password" disabled={blocked} placeholder="使用临时 AccessKey 时填写" /></Form.Item></details><div className="settings-security">密钥在服务端加密保存，不回显到浏览器。</div></> : <><div className="two-fields"><Form.Item label="地域" name="region" rules={[{ required: true, message: '请输入地域 ID' }]}><Input placeholder="cn-hangzhou" disabled={blocked} /></Form.Item><Form.Item label="可用区" name="zone" rules={[{ required: true, message: '请输入可用区 ID' }]}><Input placeholder="cn-hangzhou-h" disabled={blocked} /></Form.Item></div><div className="settings-security">当前：{account.region || '未配置'} / {account.zone || '未配置'}</div></>}<div className="settings-actions"><span className="muted">{verified?.verified_at || account.verified_at ? `验证于 ${formatTime(verified?.verified_at || account.verified_at)}` : '尚未验证'}</span><span className="bar-spacer" />{tab === 'account' && <Button onClick={() => void verify()} loading={busy === 'verify'} disabled={!!busy}>测试连接</Button>}<Button type="primary" htmlType="submit" loading={busy === 'save'} disabled={blocked || !!busy}>验证并保存</Button></div></Form></section>{tab === 'resources' ? <section className="settings-panel network-panel"><div className="settings-heading"><h2>Worker 资源</h2><span className="bar-spacer" /><Status value={config.ready ? 'ready' : 'pending'} label={config.ready ? '已就绪' : '待准备'} /></div><Descriptions size="small" column={1} items={[{ key: 'vpc', label: 'VPC', children: <Typography.Text copyable={!!config.resources.vpc_id} className="mono">{config.resources.vpc_id || '—'}</Typography.Text> }, { key: 'vsw', label: '交换机', children: config.resources.vswitch_ids?.map(id => <div key={id}><Typography.Text copyable className="mono">{id}</Typography.Text></div>) || '—' }, { key: 'sg', label: '安全组', children: <Typography.Text copyable={!!config.resources.security_group_id} className="mono">{config.resources.security_group_id || '—'}</Typography.Text> }, { key: 'image', label: '系统镜像', children: <span className="mono break-text">{config.resources.image_id || '—'}</span> }, { key: 'types', label: '候选规格', children: <div className="spec-list">{config.resources.instance_types?.map(type => <span className="mono" key={type}>{type}</span>) || '—'}</div> }, { key: 'model', label: '实例策略', children: '抢占式 · 无保护期 · 自动补齐目标数量' }]} />{config.error && <details className="config-error"><summary>控制面配置需要检查</summary><pre>{config.error}</pre></details>}<div className="settings-actions"><span className="muted">仅准备网络，不启动实例</span><span className="bar-spacer" /><Button onClick={() => void setup()} loading={busy === 'setup'} disabled={blocked || !!busy || !config.has_credentials}>一键准备网络</Button></div></section> : <aside className="account-summary"><h3>当前连接</h3><dl><dt>云账号 ID</dt><dd className="mono">{verified?.account_id || account.account_id || '验证后显示'}</dd><dt>地域 / 可用区</dt><dd>{account.region || '—'} / {account.zone || '—'}</dd><dt>网络资源</dt><dd><Status value={config.ready ? 'ready' : 'pending'} label={config.ready ? '已就绪' : '待准备'} /></dd><dt>凭据更新</dt><dd>新配置验证通过后生效</dd></dl></aside>}</div>
}

function ToolResources({ node }: { node: Node }) {
  const m = node.worker?.metrics
  if (m?.tools_processes === undefined) return null
  const historical = ['offline', 'released', 'unknown'].includes(node.status)
  const tools = [
    { key: 'masscan', name: 'Masscan' }, { key: 'nmap', name: 'Nmap' },
    { key: 'web_probe', name: 'Web 采集' }, { key: 'fingerprint', name: '指纹引擎' },
    { key: 'httpx', name: 'HTTPx CLI' }, { key: 'nuclei', name: 'Nuclei' },
  ]
  return <>
    <div className="filter-bar">
      <strong>{historical ? '工具占用 · 最后记录' : '工具占用'}</strong>
      <span className="muted">{m.tools_processes} 个进程</span>
      <span className="bar-spacer" />
      {!historical && m.admission_paused !== undefined && <Tag color={m.admission_paused ? 'orange' : 'green'}>{m.admission_paused ? '暂停接单' : '可接单'}</Tag>}
    </div>
    <Table size="small" rowKey="key" pagination={false} dataSource={tools} columns={[
      { title: '工具', dataIndex: 'name' },
      { title: '进程', key: 'processes', width: 75, render: (_: unknown, t: { key: string }) => m[`${t.key}_processes`] ?? '—' },
      { title: <Tooltip title="直接受控进程的 RSS 合计，含共享页；每秒采样。">RSS 内存</Tooltip>, key: 'rss', width: 120, render: (_: unknown, t: { key: string }) => m[`${t.key}_rss_mib`] !== undefined ? `${m[`${t.key}_rss_mib`].toFixed(1)} MiB` : '—' },
    ]} />
    <Descriptions size="small" column={2} className="metric-caption" items={[
      { key: 'connections', label: <Tooltip title="工具执行的连接准入估算，不是实际网络连接计数。">连接预算</Tooltip>, children: m.connection_slots_used !== undefined ? `${m.connection_slots_used} / ${m.connection_slots_limit}` : '—' },
      { key: 'upload', label: '待上传', children: m.upload_queued_bytes !== undefined ? `${(m.upload_queued_bytes / 1024).toFixed(1)} KiB` : '—' },
      { key: 'agent', label: 'Agent RSS', children: m.agent_rss_mib !== undefined ? `${m.agent_rss_mib.toFixed(1)} MiB` : '—' },
      { key: 'peak', label: '工具 RSS 峰值', children: m.peak_tools_rss_mib !== undefined ? `${m.peak_tools_rss_mib.toFixed(1)} MiB` : '—' },
    ]} />
  </>
}

function NodeDrawer({ node, close, openRun }: { node?: Node; close: () => void; openRun: (id: string) => void }) {
  const w = node?.worker
  const m = w?.metrics
  return <Drawer open={!!node} onClose={close} title="Worker 详情" size={620} destroyOnHidden>{node && <><div className="node-detail-heading"><CloudServerOutlined /><h2>{node.name}</h2><Status value={node.status} /></div><Typography.Text copyable className="mono muted">{node.id}</Typography.Text><div className="node-metrics"><div><span>CPU</span><b>{m?.cpu_percent !== undefined ? `${m.cpu_percent.toFixed(1)}%` : '—'}</b></div><div><span>可用内存</span><b>{m?.mem_available_mib !== undefined ? `${Math.round(m.mem_available_mib)} MiB` : '—'}</b></div><div><span>工具 RSS</span><b>{m?.tools_rss_mib !== undefined ? `${m.tools_rss_mib.toFixed(1)} MiB` : '—'}</b></div></div><div className="muted metric-caption">最后采样：{formatTime(w?.last_heartbeat)}</div><Descriptions size="small" column={2} items={[{ key: 'zone', label: '可用区', children: node.zone || '—' }, { key: 'spec', label: '规格', children: node.cores ? `${node.cores} 核 / ${(node.memory / 1024).toFixed(0)} GB` : node.status === 'released' ? '未记录' : '待同步' }, { key: 'type', label: '实例型号', children: <span className="mono">{node.type || '—'}</span>, span: 2 }, { key: 'agent', label: 'Agent', children: w?.agent_version || '尚未注册' }, { key: 'cloud', label: '云状态', children: node.cloud?.state || '—' }, { key: 'created', label: '创建时间', children: formatTime(node.cloud?.created_at) }, { key: 'updated', label: '同步时间', children: formatTime(node.cloud?.updated_at) }]} />{node.reason && <Alert className="inline-alert" type={node.status === 'unknown' ? 'warning' : 'info'} showIcon title="节点状态信息" description={node.reason} />}<ToolResources node={node} /><h3 className="section-caption">当前执行（{w?.active_tasks?.length || 0}）</h3>{w?.active_tasks?.length ? <div className="node-task-list">{w.active_tasks.map(task => <div key={task.id}><button className="text-link" onClick={() => { close(); openRun(task.run_id) }}>{task.run_name}</button><span className="mono task-targets">{(task.targets?.length ? task.targets : [task.target]).join(" · ")}</span><Tag>{task.type === 'port' ? '端口扫描' : task.type === 'service' ? '服务指纹' : task.type === 'poc' ? 'PoC 检查' : 'HTTP 指纹'}</Tag></div>)}</div> : <div className="compact-note">{node.status === 'released' ? '实例已释放' : node.status === 'starting' ? '等待 Agent 注册并领取任务' : '没有正在执行的任务'}</div>}</>}</Drawer>
}

export function WorkersPage({ api, openRun, active = true }: { api: ApiClient; openRun: (id: string) => void; active?: boolean }) {
  const { message, modal } = AntApp.useApp()
  const [tab, setTab] = useState('nodes')
  const [filter, setFilter] = useState('current')
  const [search, setSearch] = useState('')
  const [desired, setDesired] = useState(0)
  const [dirty, setDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [maintaining, setMaintaining] = useState('')
  const [selected, setSelected] = useState<string>()
  useEffect(() => { if (!active) setSelected(undefined) }, [active])
  const poolData = useLoad<Pool>(api, '/worker-pool', 10000)
  const workerData = useLoad<{ items: Worker[] }>(api, '/workers', 10000)
  const cloudNodes = useLoad<{ items: CloudInstance[] }>(api, '/cloud/aliyun/instances', 10000)
  const cloud = useLoad<CloudConfig>(api, '/cloud/aliyun')
  const pool = poolData.data
  useEffect(() => { if (pool && !dirty) setDesired(pool.desired_workers) }, [pool, dirty])
  const nodes = useMemo(() => combineNodes(workerData.data?.items || [], cloudNodes.data?.items || []), [workerData.data, cloudNodes.data])
  const live = nodes.filter(n => n.status !== 'released')
  const attention = live.filter(n => ['unknown', 'offline', 'interruption'].includes(n.status))
  const shown = nodes.filter(n => (filter === 'history' ? n.status === 'released' : filter === 'attention' ? attention.includes(n) : filter === 'busy' ? n.status === 'busy' : n.status !== 'released') && `${n.name} ${n.id} ${n.zone}`.toLowerCase().includes(search.toLowerCase()))
  const reload = async () => { await Promise.all([poolData.reload(), workerData.reload(), cloudNodes.reload(), cloud.reload()]) }
  const update = async (enabled: boolean, amount: number) => {
    if (!pool) return
    setSaving(true)
    try { await api.request('/worker-pool', { method: 'PATCH', body: JSON.stringify({ desired_workers: amount, enabled, expected_generation: pool.generation }) }); setDirty(false); await reload(); message.success(enabled ? `目标数量已设为 ${amount} 台` : '正在排空并释放 Worker') }
    catch (e) { message.error(e instanceof Error ? e.message : '更新失败'); await poolData.reload() } finally { setSaving(false) }
  }
  const setMaintenance = async (worker: Worker) => {
    if (!worker.session_id) return
    setMaintaining(worker.id)
    try {
      const result = await api.request<{ maintenance: boolean; active_tasks: number }>(`/workers/${encodeURIComponent(worker.id)}/maintenance`, { method: 'POST', body: JSON.stringify({ enabled: !worker.maintenance, expected_session_id: worker.session_id }) })
      await reload()
      message.success(result.maintenance ? (result.active_tasks ? `维护已开启，等待 ${result.active_tasks} 项执行结束` : '维护已开启，节点已空闲') : '已恢复领取任务')
    } catch (e) { message.error(e instanceof Error ? e.message : '更新维护状态失败'); await workerData.reload() }
    finally { setMaintaining('') }
  }
  const apply = () => {
    if (pool?.enabled && desired < pool.desired_workers) modal.confirm({ title: `将目标数量缩减到 ${desired} 台？`, content: '多余节点会先回传结果，再释放实例。', okText: '缩减数量', cancelText: '返回', onOk: () => update(true, desired) })
    else void update(true, desired)
  }
  const columns = [
    { title: '节点', key: 'node', width: 260, render: (_: unknown, n: Node) => <div className="node-name"><span className="node-icon"><CloudServerOutlined /></span><div className="name-cell"><button className="text-link mono" onClick={() => setSelected(n.id)}>{n.name}</button>{n.name !== n.id && <span className="cell-secondary mono">{n.id}</span>}</div></div> },
    { title: '状态', key: 'status', width: 130, render: (_: unknown, n: Node) => <Space size={4} wrap><Status value={n.status} />{n.worker?.maintenance && <Tag color="blue">维护</Tag>}</Space> },
    { title: '当前任务', key: 'task', width: 220, render: (_: unknown, n: Node) => n.worker?.active_tasks?.length ? <div className="name-cell"><button className="text-link" onClick={() => openRun(n.worker!.active_tasks![0].run_id)}>{n.worker.active_tasks[0].run_name}</button><span className="cell-secondary">{n.worker.active_tasks.length} 个执行步骤 · {n.worker.active_tasks.map(t => t.type).filter((v, i, a) => a.indexOf(v) === i).map(t => t === 'port' ? '端口' : t === 'service' ? '服务' : t === 'poc' ? 'PoC' : 'HTTP').join(' / ')}</span></div> : <span className="muted">{n.status === 'starting' ? '等待注册' : n.status === 'draining' || n.status === 'interruption' ? '停止领取任务' : '—'}</span> },
    { title: '规格 / 可用区', key: 'spec', width: 165, render: (_: unknown, n: Node) => <div>{n.cores ? `${n.cores} 核 / ${(n.memory / 1024).toFixed(0)} GB` : n.status === 'released' ? '未记录' : '待同步'}<div className="cell-secondary mono">{n.zone || '—'}</div></div> },
    { title: 'CPU / 可用内存', key: 'metrics', width: 155, render: (_: unknown, n: Node) => {
      const m = n.worker?.metrics
      const stale = ['offline', 'released', 'unknown'].includes(n.status)
      return m?.mem_total_mib && !stale ? <div><div className="metric-mini"><span>{m.cpu_percent?.toFixed(1) ?? '—'}%</span><span className="progress-track"><i style={{ width: `${Math.min(100, m.cpu_percent || 0)}%` }} /></span></div><span className="cell-secondary">可用 {Math.round(m.mem_available_mib || 0)} / {Math.round(m.mem_total_mib)} MiB</span></div> : <span className="muted">{stale ? '—' : '待采样'}</span>
    } },
    { title: '最后心跳', key: 'time', width: 100, render: (_: unknown, n: Node) => <Tooltip title={formatTime(n.worker?.last_heartbeat)}><span className="muted">{relativeTime(n.worker?.last_heartbeat)}</span></Tooltip> },
    { title: '', key: 'more', width: 135, render: (_: unknown, n: Node) => <Space size={0}><Button type="link" size="small" onClick={() => setSelected(n.id)}>详情</Button>{n.worker?.session_id && (['ready', 'busy'].includes(n.status) || n.worker.maintenance) && <Button type="link" size="small" loading={maintaining === n.worker.id} disabled={!!maintaining && maintaining !== n.worker.id} onClick={() => void setMaintenance(n.worker!)}>{n.worker.maintenance ? '恢复调度' : '维护'}</Button>}</Space> },
  ]
  return <><div className="page-bar worker-page-bar"><h1>Workers</h1><div className="page-tabs" role="tablist" aria-label="Worker 页面">{[['nodes', '节点'], ['account', '阿里云账号'], ['resources', '资源配置'], ['scheduler', '调度策略']].map(([key, label]) => <button key={key} role="tab" aria-selected={tab === key} onClick={() => setTab(key)}>{label}</button>)}</div><span className="bar-spacer" />{tab !== 'scheduler' && <Refresh onClick={() => void reload()} loading={poolData.loading && !pool} />}</div><LoadError error={poolData.error || workerData.error || cloudNodes.error || cloud.error} retry={() => void reload()} />{tab === 'nodes' ? <><div className="pool-toolbar"><Status value={pool?.enabled ? 'running' : 'stopped'} label={pool?.enabled ? '节点池运行中' : '节点池已停止'} /><div className="pool-counts"><span>在线 <b>{number(pool?.healthy_workers)}</b></span><span>启动中 <b>{number(pool?.starting_workers)}</b></span><span>排空 <b>{number(pool?.draining_workers)}</b></span>{attention.length > 0 && <button className="text-link amber" onClick={() => setFilter('attention')}>需关注 {attention.length}</button>}</div><span className="bar-spacer" /><label htmlFor="worker-count">目标数量</label><InputNumber id="worker-count" aria-label="目标 Worker 数量" min={0} max={1000} precision={0} value={desired} onChange={v => { setDesired(v || 0); setDirty(true) }} /><Button type="primary" icon={pool?.enabled ? undefined : <PlayCircleOutlined />} disabled={!pool || !pool.configured || saving || (!pool.enabled && desired === 0) || (pool.enabled && desired === pool.desired_workers)} loading={saving} onClick={apply}>{pool?.enabled ? '应用数量' : `启动 ${desired} 台`}</Button>{pool?.enabled && <Button danger icon={<StopOutlined />} disabled={saving} onClick={() => modal.confirm({ title: '停止 Worker 池？', content: '停止领取新任务，回传已有结果后释放全部实例。扫描结果会保留。', okText: '停止并释放', cancelText: '返回', okButtonProps: { danger: true }, onOk: () => update(false, pool.desired_workers) })}>停止</Button>}</div>{pool?.error && <Alert className="inline-alert" type="warning" showIcon title="云调度异常" description={pool.error} />}{pool && !pool.configured && <div className="prerequisite"><span>{cloud.data?.has_credentials ? '云网络尚未就绪' : '尚未配置阿里云账号'}</span><Button size="small" type="link" onClick={() => setTab(cloud.data?.has_credentials ? 'resources' : 'account')}>前往配置</Button></div>}<section className="table-panel"><div className="filter-bar"><Segmented value={filter} onChange={setFilter} options={[{ label: `当前 ${live.length}`, value: 'current' }, { label: `需关注 ${attention.length}`, value: 'attention' }, { label: '扫描中', value: 'busy' }, { label: `已释放 ${nodes.length - live.length}`, value: 'history' }]} /><Input className="search-input" prefix={<SearchOutlined />} aria-label="搜索节点" placeholder="搜索节点 / 实例 ID" allowClear value={search} onChange={e => setSearch(e.target.value)} /></div><Table rowKey="id" size="small" columns={columns} dataSource={shown} loading={workerData.loading && !workerData.data} scroll={{ x: 1060 }} pagination={{ defaultPageSize: 50, showSizeChanger: true, pageSizeOptions: [20, 50, 100], showTotal: n => `${n} 台节点` }} locale={{ emptyText: <NoData text={filter === 'current' ? pool?.enabled ? '等待实例申请和 Agent 注册' : '节点池已停止，设置数量后启动' : '没有符合条件的节点'} /> }} /></section></> : tab === 'scheduler' ? <SchedulerPanel api={api} /> : cloud.data && <CloudSettings key={`${tab}-${cloud.data.account.revision}`} api={api} config={cloud.data} pool={pool} active={cloudNodes.data?.items.some(n => !n.released) || false} tab={tab} reload={reload} />}<NodeDrawer node={nodes.find(n => n.id === selected)} close={() => setSelected(undefined)} openRun={openRun} /></>
}
