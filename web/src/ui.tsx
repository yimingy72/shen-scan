import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { Alert, Button, Empty, Tag, Tooltip } from 'antd'
import { ReloadOutlined, ScanOutlined } from '@ant-design/icons'
import { ApiClient } from './api'

type LoadCacheEntry = { data: unknown; at: number }
const loadCache = new Map<string, LoadCacheEntry>()
const LOAD_CACHE_LIMIT = 120
const LOAD_CACHE_FRESH_MS = 10_000
const PERSISTED_LOAD_PATH = '/runs?summary=true'
const PERSISTED_LOAD_KEY = 'scan-platform:runs-cache'
const PERSISTED_LOAD_MAX_AGE_MS = 5 * 60_000

const apiIdentities = new WeakMap<ApiClient, number>()
let apiIdentitySequence = 0
function apiIdentity(api: ApiClient) {
  let identity = apiIdentities.get(api)
  if (identity === undefined) {
    identity = ++apiIdentitySequence
    apiIdentities.set(api, identity)
  }
  return identity
}
function loadCacheKey(api: ApiClient, path: string) {
  return `${apiIdentity(api)}:${path}`
}
function readCache<T>(api: ApiClient, path: string | null) {
  if (!path) return undefined
  const entry = loadCache.get(loadCacheKey(api, path)) as LoadCacheEntry & { data: T } | undefined
  if (entry || path !== PERSISTED_LOAD_PATH) return entry
  try {
    const persisted = JSON.parse(sessionStorage.getItem(PERSISTED_LOAD_KEY) || 'null') as LoadCacheEntry | null
    if (persisted && typeof persisted.at === 'number' && Date.now() - persisted.at < PERSISTED_LOAD_MAX_AGE_MS) return persisted as LoadCacheEntry & { data: T }
  } catch { /* session storage may be unavailable */ }
  return undefined
}
function writeCache(api: ApiClient, path: string, data: unknown) {
  const key = loadCacheKey(api, path)
  const entry = { data, at: Date.now() }
  loadCache.delete(key)
  loadCache.set(key, entry)
  while (loadCache.size > LOAD_CACHE_LIMIT) {
    const oldest = loadCache.keys().next().value
    if (oldest === undefined) break
    loadCache.delete(oldest)
  }
  if (path === PERSISTED_LOAD_PATH) {
    try { sessionStorage.setItem(PERSISTED_LOAD_KEY, JSON.stringify(entry)) } catch { /* session storage may be unavailable */ }
  }
}
export function clearLoadCache() {
  loadCache.clear()
  try { sessionStorage.removeItem(PERSISTED_LOAD_KEY) } catch { /* session storage may be unavailable */ }
}

const PageActiveContext = createContext(true)
export function usePageActive() { return useContext(PageActiveContext) }
export function PageActivity({ active, children }: { active: boolean; children: ReactNode }) {
  return <PageActiveContext.Provider value={active}>{children}</PageActiveContext.Provider>
}

type LoadState<T> = { path: string | null; data?: T; error: string; loading: boolean }

export function useLoad<T>(api: ApiClient, path: string | null, interval = 0) {
  const active = useContext(PageActiveContext)
  const cached = readCache<T>(api, path)
  const [state, setState] = useState<LoadState<T>>(() => ({ path, data: cached?.data, error: '', loading: !!path && !cached }))
  const sequence = useRef(0)
  const activeRequest = useRef<AbortController | null>(null)
  const wasActive = useRef(active)

  const fetchData = useCallback(async (options?: { background?: boolean }) => {
    const target = path
    if (!target) {
      setState(previous => previous.path === null ? previous : { path: null, error: '', loading: false })
      return
    }
    const cachedValue = readCache<T>(api, target)
    const seq = ++sequence.current
    activeRequest.current?.abort()
    const controller = new AbortController()
    activeRequest.current = controller
    setState(previous => {
      const data = previous.path === target ? previous.data : cachedValue?.data
      return { path: target, data, error: '', loading: !options?.background || data === undefined }
    })
    try {
      const value = await api.request<T>(target, { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(90000)]) })
      writeCache(api, target, value)
      if (seq === sequence.current) setState({ path: target, data: value, error: '', loading: false })
    } catch (reason) {
      if (seq === sequence.current && !controller.signal.aborted) {
        const message = reason instanceof Error ? reason.message : '加载失败'
        setState(previous => previous.path === target
          ? { ...previous, error: message, loading: false }
          : { path: target, data: cachedValue?.data, error: message, loading: false })
      }
    } finally {
      if (seq === sequence.current) {
        activeRequest.current = null
        setState(previous => previous.loading ? { ...previous, loading: false } : previous)
      }
    }
  }, [api, path])

  useEffect(() => {
    const cachedValue = readCache<T>(api, path)
    setState(previous => previous.path === path
      ? { ...previous, data: previous.data ?? cachedValue?.data, error: '', loading: previous.data === undefined && !cachedValue }
      : { path, data: cachedValue?.data, error: '', loading: !!path && !cachedValue })
    if (path && (!cachedValue || Date.now() - cachedValue.at > LOAD_CACHE_FRESH_MS)) void fetchData({ background: true })
    return () => { ++sequence.current; activeRequest.current?.abort(); activeRequest.current = null }
  }, [api, path, fetchData])

  useEffect(() => {
    if (active && !wasActive.current && path) {
      const cachedValue = readCache<T>(api, path)
      if (!cachedValue || Date.now() - cachedValue.at > LOAD_CACHE_FRESH_MS) void fetchData({ background: true })
    }
    wasActive.current = active
  }, [active, api, path, fetchData])

  useEffect(() => {
    if (!path || !interval || !active) return
    let stopped = false
    let timer: number | undefined
    const poll = async () => {
      if (!document.hidden && !activeRequest.current) await fetchData({ background: true })
      if (!stopped) timer = window.setTimeout(poll, interval)
    }
    timer = window.setTimeout(poll, interval)
    return () => { stopped = true; if (timer !== undefined) clearTimeout(timer) }
  }, [active, fetchData, interval, path])

  const reload = useCallback(() => fetchData(), [fetchData])
  const current = state.path === path
  const visible = current ? state : undefined
  const fallback = current ? undefined : readCache<T>(api, path)
  return {
    data: visible ? visible.data : fallback?.data,
    error: visible ? visible.error : '',
    loading: visible ? visible.loading : !!path && !fallback,
    reload,
  }
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
