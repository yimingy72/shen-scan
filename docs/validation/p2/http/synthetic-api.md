# 本地合成夹具：完整HTTP报文

状态：未利用。以下数据用于验证接口与页面显示，工具RSS/CPU值是显式合成值，不是实测性能。实际Linux采样、真实helper检查另见原始日志。令牌用占位符，正文不截断；Markdown使用LF，响应体为客户端解码后的实体。

## heartbeat-synthetic-telemetry

URL：`http://127.0.0.1:18581/api/workers/heartbeat`

```http
POST /api/workers/heartbeat HTTP/1.1
Host: 127.0.0.1:18581
Authorization: Bearer ${P2_LOCAL_TOKEN}
Accept: application/json
Accept-Encoding: identity
Connection: close
Content-Type: application/json
Content-Length: 697

{"worker_id": "12901675-92d4-405c-8960-36779591090b", "session_id": "p2-preview-session", "status": "ready", "metrics": {"active_tasks": 0, "cpu_percent": 12.5, "mem_total_mib": 2048, "mem_available_mib": 1400, "agent_rss_mib": 35, "tools_rss_mib": 178.5, "peak_tools_rss_mib": 220, "tools_processes": 4, "masscan_processes": 0, "masscan_rss_mib": 0, "nmap_processes": 1, "nmap_rss_mib": 24.5, "web_probe_processes": 2, "web_probe_rss_mib": 104, "fingerprint_processes": 1, "fingerprint_rss_mib": 50, "httpx_processes": 0, "httpx_rss_mib": 0, "nuclei_processes": 0, "nuclei_rss_mib": 0, "connection_slots_used": 6, "connection_slots_limit": 16, "upload_queued_bytes": 2048, "admission_paused": 0}}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 21:29:07 GMT
Content-Length: 126
Connection: close

{"action":"continue","control_generation":1,"prefer_service":true,"preference_ttl_seconds":20,"reason":"","stop_task_ids":[]}

```

## register

URL：`http://127.0.0.1:18581/api/workers/register`

```http
POST /api/workers/register HTTP/1.1
Host: 127.0.0.1:18581
Authorization: Bearer ${P2_LOCAL_TOKEN}
Accept: application/json
Accept-Encoding: identity
Connection: close
Content-Type: application/json
Content-Length: 194

{"instance_id": "p2-local-synthetic", "hostname": "本地验收 · 合成节点", "session_id": "p2-preview-session", "agent_version": "p2-preview", "spec": {"cpu_cores": 2, "memory_mib": 2048}}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 21:29:07 GMT
Content-Length: 158
Connection: close

{"heartbeat_seconds": 10, "worker_id": "12901675-92d4-405c-8960-36779591090b", "worker_token": "${REDACTED_TOKEN}"}
```

## scheduler-service-priority

URL：`http://127.0.0.1:18581/api/scheduler/status`

```http
GET /api/scheduler/status HTTP/1.1
Host: 127.0.0.1:18581
Authorization: Bearer ${P2_LOCAL_TOKEN}
Accept: application/json
Accept-Encoding: identity
Connection: close


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 21:29:07 GMT
Content-Length: 726
Connection: close

{"http_budget":{"active_connect_ips":0,"admission_burst":1,"cluster_rps":250,"enforcement":"cooperative_request_admission","per_connect_ip_rps":10,"permit_lifetime_ms":500,"unexpired_permit_receipts":0},"port_batch":{"size":4,"samples":0,"reason":"cold"},"port_range":"1-65535","service_batch":{"size":32,"samples":0,"reason":"cold"},"service_pressure":{"available":true,"prefer_service":true,"observed_at":"2026-10-17T21:29:07.933143Z","sample_limit":1024,"candidate_tasks":12,"sampled_tasks":12,"sampled_endpoints":12,"truncated":false,"work_is_lower_bound":false,"oldest_wait_seconds":60.020641,"cost_samples":0,"reason":"service_backlog"},"stages":[{"stage":"service","queued":12,"running":0,"oldest_seconds":60.021843}]}

```
