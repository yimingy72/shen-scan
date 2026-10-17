import { useCallback, useEffect, useRef, useState } from 'react'
import { Alert, Button, Empty, Tag, Tooltip } from 'antd'
import { ReloadOutlined, ScanOutlined } from '@ant-design/icons'
import { ApiClient } from './api'

export function useLoad<T>(api: ApiClient, path: string | null, interval = 0) {
  const [data, setData] = useState<T>()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const sequence = useRef(0)
  const active = useRef<AbortController | null>(null)
  const reload = useCallback(async () => {
    const seq = ++sequence.current
    active.current?.abort()
    if (!path) { setData(undefined); setLoading(false); return }
    const controller = new AbortController()
    active.current = controller
    setLoading(true)
    try {
      const value = await api.request<T>(path, { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(90000)]) })
      if (seq === sequence.current) { setData(value); setError('') }
    } catch (reason) {
      if (seq === sequence.current && !controller.signal.aborted) setError(reason instanceof Error ? reason.message : '加载失败')
    } finally { if (seq === sequence.current) { active.current = null; setLoading(false) } }
  }, [api, path])
  useEffect(() => {
    setData(undefined); setError(''); void reload()
    return () => { ++sequence.current; active.current?.abort() }
  }, [reload])
  useEffect(() => {
    if (!path || !interval) return
    let stopped = false
    let timer: number | undefined
    const poll = async () => {
      // Let slow requests finish; a timer must not continually cancel them.
      if (!document.hidden && !active.current) await reload()
      if (!stopped) timer = window.setTimeout(poll, interval)
    }
    timer = window.setTimeout(poll, interval)
    return () => { stopped = true; clearTimeout(timer) }
  }, [reload, path, interval])
  return { data, error, loading, reload }
}

const statuses: Record<string, [string, string]> = {
  pending: ['排队中', 'muted'], queued: ['排队中', 'muted'], running: ['执行中', 'blue'], completed: ['已完成', 'green'],
  cancelled: ['已取消', 'muted'], cancelling: ['取消中', 'amber'], failed: ['失败', 'red'], partial: ['部分完成', 'amber'], paused: ['已暂停', 'amber'],
  ready: ['空闲', 'green'], busy: ['扫描中', 'blue'], starting: ['启动中', 'blue'], draining: ['排空中', 'amber'],
  interruption: ['即将回收', 'amber'], offline: ['离线', 'red'], released: ['已释放', 'muted'], unknown: ['待确认', 'amber'], stopped: ['已停止', 'muted'],
}
export function Status({ value, label }: { value: string; label?: string }) {
  const [text, tone] = statuses[value] || [value, 'muted']
  return <span className={`status-dot ${tone}`}>{label || text}</span>
}
export function Brand() { return <div className="brand"><span className="brand-icon"><ScanOutlined /></span><span>SHEN</span></div> }
export function Refresh({ onClick, loading }: { onClick: () => void; loading?: boolean }) { return <Button icon={<ReloadOutlined />} onClick={onClick} loading={loading}>刷新</Button> }
export function LoadError({ error, retry }: { error?: string; retry?: () => void }) { return error ? <Alert className="inline-alert" type="error" showIcon title={error} action={retry && <Button size="small" onClick={retry}>重试</Button>} /> : null }
export function NoData({ text }: { text: string }) { return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={text} /> }
export function SmallTags({ items, max = 5 }: { items: string[]; max?: number }) {
  return items.length ? <span className="tag-list">{items.slice(0, max).map(item => <Tag key={item}>{item}</Tag>)}{items.length > max && <Tooltip title={items.slice(max).join(' · ')}><Tag>+{items.length - max}</Tag></Tooltip>}</span> : <span className="muted">—</span>
}
export const number = (n?: number) => (n ?? 0).toLocaleString('zh-CN')
export function shortTime(value?: string) {
  if (!value) return '—'
  return new Date(value).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}
export function relativeTime(value?: string) {
  if (!value) return '待注册'
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000))
  if (!Number.isFinite(seconds)) return '—'
  return seconds < 60 ? `${seconds} 秒前` : seconds < 3600 ? `${Math.floor(seconds / 60)} 分钟前` : seconds < 86400 ? `${Math.floor(seconds / 3600)} 小时前` : `${Math.floor(seconds / 86400)} 天前`
}
export function isIP(target: string) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(target) || target.includes(':') }
