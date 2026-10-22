import { useEffect, useState } from 'react'
import { App as AntApp, Button, Dropdown, Form, Modal, Select, Space } from 'antd'
import { CopyOutlined, DeleteOutlined, DownloadOutlined, MoreOutlined } from '@ant-design/icons'
import { ApiClient, type Run } from './api'
import { LoadError, usePageActive } from './ui'

export function TaskTools({ api, run, copy, deleted, compact = false }: {
  api: ApiClient; run: Run; copy: (id: string) => void; deleted: (id: string) => void; compact?: boolean
}) {
  const { message, modal } = AntApp.useApp()
  const active = usePageActive()
  const [exportOpen, setExportOpen] = useState(false)
  const [kind, setKind] = useState('targets')
  const [format, setFormat] = useState('csv')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => { if (!active) setExportOpen(false) }, [active])
  const exportResults = async () => {
    setBusy(true); setError('')
    try {
      const blob = await api.blob(`/runs/${encodeURIComponent(run.id)}/export?kind=${kind}&format=${format}`)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `scan-${run.id}-${kind}.${format}`
      document.body.appendChild(link); link.click(); link.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 30000)
      setExportOpen(false)
    } catch (e) { setError(e instanceof Error ? e.message : '导出失败') }
    finally { setBusy(false) }
  }
  const remove = () => modal.confirm({
    title: `删除“${run.name}”？`,
    content: '将永久删除该任务的结果、报文和截图。请先导出需要保留的数据。',
    okText: '删除任务', cancelText: '保留', okButtonProps: { danger: true },
    onOk: async () => {
      try {
        await api.request(`/runs/${encodeURIComponent(run.id)}`, { method: 'DELETE' })
        deleted(run.id); message.success('任务及关联结果已删除')
      } catch (e) {
        message.error(e instanceof Error && 'status' in e && e.status === 409 ? '任务仍有执行或尚未确认停止，请稍后再删除' : e instanceof Error ? e.message : '删除失败')
        throw e
      }
    },
  })
  const openExport = () => { setKind('targets'); setError(''); setExportOpen(true) }
  const canDelete = ['completed', 'partial', 'failed', 'cancelled'].includes(run.status)
  const items = [
    ...(compact ? [{ key: 'copy', label: '复制为新任务', icon: <CopyOutlined />, onClick: () => copy(run.id) }, { key: 'export', label: '导出结果', icon: <DownloadOutlined />, onClick: openExport }] : []),
    { key: 'delete', label: '删除任务', icon: <DeleteOutlined />, danger: true, disabled: !canDelete, onClick: remove },
  ]
  return <><Space size={4}>
    {!compact && <><Button size="small" icon={<CopyOutlined />} onClick={() => copy(run.id)}>复制任务</Button><Button size="small" icon={<DownloadOutlined />} onClick={openExport}>导出</Button></>}
    <Dropdown menu={{ items }} trigger={['click']}><Button type="text" size="small" icon={<MoreOutlined />} aria-label={`任务操作：${run.name}`} /></Dropdown>
  </Space><Modal title="导出任务结果" open={exportOpen} onCancel={() => setExportOpen(false)} onOk={() => void exportResults()} okText="下载" cancelText="取消" confirmLoading={busy}>
    <LoadError error={error} /><Form layout="vertical"><Form.Item label="导出内容"><Select aria-label="导出内容" value={kind} onChange={setKind} options={[{ value: 'targets', label: '目标汇总' }, { value: 'ports', label: '开放端口与服务' }, { value: 'http', label: 'HTTP 端点与指纹' }, ...(run.poc_enabled ? [{ value: 'findings', label: 'PoC 检查结果' }] : [])]} /></Form.Item><Form.Item label="文件格式"><Select aria-label="文件格式" value={format} onChange={setFormat} options={[{ value: 'csv', label: 'CSV · 表格' }, { value: 'json', label: 'JSON · 结构化数据' }]} /></Form.Item></Form>
    <p className="muted">导出整个任务的结果与覆盖状态，包含导出时点；不受当前分页和筛选限制。</p>
  </Modal></>
}
