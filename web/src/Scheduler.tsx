import { Descriptions, Table, Tag, Tooltip } from 'antd'
import { ApiClient } from './api'
import { LoadError, Refresh, useLoad } from './ui'

type Tuning = { size: number; samples: number; seconds_per_item?: number; reason: string }
type Stage = { stage: string; queued: number; running: number; oldest_seconds: number }
type Scheduling = {
  http_budget: { per_connect_ip_rps: number; cluster_rps: number; active_connect_ips: number; permit_lifetime_ms: number }
  port_batch: Tuning; service_batch: Tuning; stages: Stage[]; port_range: string
}
const names: Record<string, string> = { port: '端口扫描', service: '端口指纹', http: 'HTTP 指纹', poc: 'PoC 检查' }
const reasons: Record<string, string> = { cold: '等待样本', observed: '按实测调优', degraded: '收紧批次' }
const wait = (seconds: number) => seconds < 60 ? `${Math.ceil(seconds)} 秒` : `${Math.floor(seconds / 60)} 分 ${Math.ceil(seconds % 60)} 秒`

export function SchedulerPanel({ api }: { api: ApiClient }) {
  const data = useLoad<Scheduling>(api, '/scheduler/status', 10000)
  const value = data.data
  const rows = ['port', 'service', 'http', 'poc'].map(stage => ({ stage, queued: 0, running: 0, oldest_seconds: 0, ...value?.stages.find(row => row.stage === stage) }))
  const tuning = (stage: string) => stage === 'port' ? value?.port_batch : stage === 'service' ? value?.service_batch : undefined
  return <section className="table-panel">
    <div className="filter-bar"><strong>调度策略</strong><Tag color="blue">TCP 1–65535</Tag><span className="bar-spacer" /><Refresh onClick={() => void data.reload()} loading={data.loading && !value} /></div>
    <LoadError error={data.error} retry={() => void data.reload()} />
    {value && <Descriptions size="small" column={3} bordered items={[
      { key: 'ip', label: '每 IP HTTP', children: <Tooltip title="所有 Worker 共用，域名按实际连接 IP 归并；限制请求许可发放速率。">{value.http_budget.per_connect_ip_rps} 请求/秒</Tooltip> },
      { key: 'cluster', label: '集群 HTTP', children: `${value.http_budget.cluster_rps} 请求/秒` },
      { key: 'active', label: '近 1 分钟 IP', children: value.http_budget.active_connect_ips },
    ]} />}
    <Table size="small" rowKey="stage" dataSource={rows} pagination={false} loading={data.loading && !value} columns={[
      { title: '阶段', dataIndex: 'stage', render: (stage: string) => names[stage] },
      { title: '排队', dataIndex: 'queued', width: 80 },
      { title: '执行中', dataIndex: 'running', width: 90 },
      { title: '最长等待', dataIndex: 'oldest_seconds', render: (seconds: number, row: Stage) => row.queued ? wait(seconds) : '—' },
      { title: '新批次上限', dataIndex: 'stage', render: (stage: string) => { const model = tuning(stage); return model ? `${model.size} ${stage === 'port' ? 'IP' : '端口'}` : stage === 'http' ? '单入口独立完成' : '按匹配模板分组' } },
      { title: '调优依据', dataIndex: 'stage', render: (stage: string) => { const model = tuning(stage); return model ? <><Tag color={model.reason === 'degraded' ? 'orange' : model.samples ? 'green' : undefined}>{reasons[model.reason] || model.reason}</Tag>{model.samples > 0 && <span className="muted">{model.samples} 次样本</span>}</> : '独立记录每项结果' } },
    ]} />
  </section>
}
