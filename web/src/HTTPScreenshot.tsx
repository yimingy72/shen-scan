import { useEffect, useRef, useState } from 'react'
import { Button, Modal, Tooltip } from 'antd'
import { PictureOutlined, ReloadOutlined } from '@ant-design/icons'
import { ApiClient, type Asset } from './api'
import { usePageActive } from './ui'

const states: Record<string, string> = { pending: '截图排队中', complete: '截图完成', partial: '页面加载不完整', error: '截图失败', not_applicable: '不适用', not_selected: '未开启' }

function ProtectedImage({ api, id, digest, thumbnail, alt }: { api: ApiClient; id: string; digest: string; thumbnail: boolean; alt: string }) {
  const holder = useRef<HTMLDivElement>(null)
  const [visible, setVisible] = useState(!thumbnail)
  const [image, setImage] = useState('')
  const [error, setError] = useState('')
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    if (visible || !holder.current) return
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) { setVisible(true); observer.disconnect() }
    }, { rootMargin: '120px' })
    observer.observe(holder.current)
    return () => observer.disconnect()
  }, [visible])
  useEffect(() => {
    if (!visible) return
    const abort = new AbortController()
    const timer = window.setTimeout(() => { setError('截图加载超时'); abort.abort() }, 20000)
    let objectURL = ''
    setImage(''); setError('')
    void api.blob(`/observations/${encodeURIComponent(id)}/screenshot${thumbnail ? '?thumbnail=true' : ''}`, abort.signal).then(blob => {
      if (abort.signal.aborted) return
      if (blob.type !== 'image/png') throw new Error('截图格式异常')
      objectURL = URL.createObjectURL(blob)
      setImage(objectURL)
    }).catch(reason => {
      if (!abort.signal.aborted) setError(reason instanceof Error ? reason.message : '截图加载失败')
    }).finally(() => window.clearTimeout(timer))
    return () => { abort.abort(); window.clearTimeout(timer); if (objectURL) URL.revokeObjectURL(objectURL) }
  }, [api, id, digest, thumbnail, visible, retry])
  return <div ref={holder} className={thumbnail ? 'http-screenshot-thumb' : 'http-screenshot-full'}>{image ? <img src={image} alt={alt} decoding="async" onError={() => { setImage(''); setError('截图无法显示') }} /> : error ? <Tooltip title={error}><Button type="text" size="small" icon={<ReloadOutlined />} aria-label="重新加载截图" onClick={event => { event.stopPropagation(); setRetry(v => v + 1) }}>重试</Button></Tooltip> : <span className="muted"><PictureOutlined />{thumbnail ? '' : ' 正在加载截图…'}</span>}</div>
}

export function HTTPScreenshot({ api, asset, detail = false }: { api: ApiClient; asset: Asset; detail?: boolean }) {
  const [open, setOpen] = useState(false)
  const active = usePageActive()
  useEffect(() => { if (!active) setOpen(false) }, [active])
  const shot = asset.screenshot
  if (!shot) return detail ? null : <span className="muted">—</span>
  const available = !!shot.sha256 && ['complete', 'partial'].includes(shot.state)
  const status = states[shot.state] || shot.state
  if (!available) return <Tooltip title={shot.error || shot.stop_reason}><span className={`screenshot-status ${shot.state === 'error' ? 'amber' : 'muted'}`}>{shot.state === 'partial' ? '截图未完成' : status}</span></Tooltip>
  return <><div className={detail ? 'screenshot-detail' : 'screenshot-cell'}>
    <div className="screenshot-trigger" role="button" tabIndex={0} aria-label={`查看首页截图：${asset.title || asset.url || asset.target}`} onClick={() => setOpen(true)} onKeyDown={event => { if (event.target === event.currentTarget && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); setOpen(true) } }}>
      <ProtectedImage api={api} id={asset.id} digest={shot.sha256!} thumbnail alt={`${asset.title || asset.url || asset.target} 首页截图`} />
    </div>
    {detail && <div><Button type="link" size="small" onClick={() => setOpen(true)}>查看首页截图</Button><span className="cell-secondary">{shot.width} × {shot.height} · {Math.ceil((shot.bytes || 0) / 1024)} KB</span></div>}
    {shot.state === 'partial' && <Tooltip title={shot.error || shot.stop_reason}><span className="screenshot-status amber">加载不完整</span></Tooltip>}
  </div><Modal open={open && active} onCancel={() => setOpen(false)} title={asset.title || '首页截图'} footer={null} width={1120} destroyOnHidden>
    <div className="screenshot-address mono">{asset.url || asset.target}</div>
    {shot.state === 'partial' && <div className="compact-note amber">{shot.stop_reason === 'screenshot-partial' ? '部分页面资源未能加载，截图保留已渲染内容。' : shot.error || '截图未完整完成，保留已渲染内容。'}</div>}
    {open && <ProtectedImage api={api} id={asset.id} digest={shot.sha256!} thumbnail={false} alt={`${asset.title || asset.target} 首页截图`} />}
  </Modal></>
}
