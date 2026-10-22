import { Table, Tooltip } from 'antd'
import { ApiClient, formatTime } from './api'
import { LoadError, Refresh, number, useLoad } from './ui'

type StorageTable = { name: string; estimated_rows: number; estimated_dead_rows: number; estimated_allocated_bytes: number; last_analyze?: string }
type StorageStatus = { observed_at: string; database_bytes: number; tables: StorageTable[] }
const labels: Record<string, string> = { runs: '扫描任务', tasks: '执行步骤', assets: '观测结果', task_batches: '提交批次', http_screenshots: '页面截图', claim_requests: '领取记录', target_quotas: '目标额度', task_item_completions: '完成记录', port_positive_receipts: '开放端口凭证', port_range_manifest: '端口覆盖清单', port_service_work: '服务识别工作', poc_template_receipts: 'PoC 完成记录', fingerprint_bundles: '指纹规则包', rule_library: '规则库' }
const bytes = (n: number) => n >= 1024 ** 3 ? `${(n / 1024 ** 3).toFixed(2)} GiB` : `${(n / 1024 ** 2).toFixed(1)} MiB`

export function StoragePanel({ api }: { api: ApiClient }) {
  const data = useLoad<StorageStatus>(api, '/storage/status', 60000)
  return <section className="table-panel"><div className="filter-bar"><strong>数据存储</strong><span className="muted">数据库 {data.data ? bytes(data.data.database_bytes) : '—'}</span><span className="bar-spacer" /><Tooltip title="数据库接口不提供所在磁盘的可用空间"><span className="muted">磁盘剩余未知</span></Tooltip><Refresh onClick={() => void data.reload()} loading={data.loading} /></div>
    <LoadError error={data.error} retry={() => void data.reload()} /><Table size="small" rowKey="name" pagination={false} loading={data.loading && !data.data} dataSource={data.data?.tables || []} columns={[
      { title: '数据', dataIndex: 'name', render: (name: string) => labels[name] || name },
      { title: '记录数（估算）', dataIndex: 'estimated_rows', align: 'right', render: number },
      { title: '待回收行（估算）', dataIndex: 'estimated_dead_rows', align: 'right', render: number },
      { title: '占用（估算）', dataIndex: 'estimated_allocated_bytes', align: 'right', render: bytes },
      { title: '统计更新时间', dataIndex: 'last_analyze', render: formatTime },
    ]} /><div className="table-pagination"><span className="muted">采样于 {formatTime(data.data?.observed_at)} · 每分钟刷新</span><a href="#runs">前往任务列表清理</a></div>
    <div className="compact-note">删除已结束任务会清理关联结果和截图；数据库文件不一定立即缩小。</div>
  </section>
}
