# R3 candidate quiet：完整请求与响应

验证状态：未利用，自建夹具；Bearer认证值占位，报文内容未截断。

记录时间：2026-10-17T20:16:38.276744+00:00
实际URL：`http://127.0.0.1:18083/api/runs`

```http
POST /api/runs HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}
Content-Type: application/json
Content-Length: 94

{"name": "p1-cloud-quiet", "targets": ["172.28.2.1"], "modes": ["port"], "poc_enabled": false}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:38 GMT
Content-Length: 512
Connection: close

{"id":"3fb7b415-c654-4fe2-b0cd-d6429f1c1d97","name":"p1-cloud-quiet","targets":["172.28.2.1"],"modes":["port"],"status":"pending","created_at":"2026-10-17T20:16:38.307972Z","updated_at":"2026-10-17T20:16:38.307972Z","task_total":1,"task_done":0,"task_failed":0,"asset_count":0,"target_count":1,"target_done":0,"open_port_count":0,"http_count":0,"input_count":1,"poc_enabled":false,"finding_count":0,"verification_finding_count":0,"check_match_count":0,"discovery_match_count":0,"poc_checked_count":0,"error":""}

```

记录时间：2026-10-17T20:17:26.477353+00:00
实际URL：`http://127.0.0.1:18083/api/runs/3fb7b415-c654-4fe2-b0cd-d6429f1c1d97`

```http
GET /api/runs/3fb7b415-c654-4fe2-b0cd-d6429f1c1d97 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:17:26 GMT
Content-Length: 514
Connection: close

{"id":"3fb7b415-c654-4fe2-b0cd-d6429f1c1d97","name":"p1-cloud-quiet","targets":["172.28.2.1"],"modes":["port"],"status":"completed","created_at":"2026-10-17T20:16:38.307972Z","updated_at":"2026-10-17T20:17:20.626886Z","task_total":1,"task_done":1,"task_failed":0,"asset_count":0,"target_count":1,"target_done":1,"open_port_count":0,"http_count":0,"input_count":1,"poc_enabled":false,"finding_count":0,"verification_finding_count":0,"check_match_count":0,"discovery_match_count":0,"poc_checked_count":0,"error":""}

```

记录时间：2026-10-17T20:17:26.794097+00:00
实际URL：`http://127.0.0.1:18083/api/runs/3fb7b415-c654-4fe2-b0cd-d6429f1c1d97/results?&limit=200&offset=0`

```http
GET /api/runs/3fb7b415-c654-4fe2-b0cd-d6429f1c1d97/results?&limit=200&offset=0 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:17:26 GMT
Content-Length: 531
Connection: close

{"items":[{"ips":[],"ports":[],"state":"completed","target":"172.28.2.1","titles":[],"products":[],"services":[],"task_done":1,"http_count":0,"open_flood":false,"port_state":"completed","task_total":1,"updated_at":"2026-10-18T04:17:20.626886+08:00","error_count":0,"task_failed":0,"technologies":[],"port_coverage":"complete","failure_reason":"","open_port_count":0,"fingerprint_count":0,"fingerprint_limited":false}],"summary":{"http_endpoints":0,"limited_targets":0,"open_ports":0,"targets":1,"targets_with_errors":0},"total":1}

```

记录时间：2026-10-17T20:17:27.044856+00:00
实际URL：`http://127.0.0.1:18083/api/runs/3fb7b415-c654-4fe2-b0cd-d6429f1c1d97/http?status=all&&limit=200&offset=0`

```http
GET /api/runs/3fb7b415-c654-4fe2-b0cd-d6429f1c1d97/http?status=all&&limit=200&offset=0 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:17:27 GMT
Content-Length: 23
Connection: close

{"items":[],"total":0}

```

记录时间：2026-10-17T20:17:27.297492+00:00
实际URL：`http://127.0.0.1:18083/api/scheduler/status`

```http
GET /api/scheduler/status HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:17:27 GMT
Content-Length: 379
Connection: close

{"http_budget":{"active_connect_ips":0,"admission_burst":1,"cluster_rps":250,"enforcement":"cooperative_request_admission","per_connect_ip_rps":10,"permit_lifetime_ms":500,"unexpired_permit_receipts":0},"port_batch":{"size":3,"samples":1,"seconds_per_item":42.19822,"reason":"observed"},"port_range":"1-65535","service_batch":{"size":32,"samples":0,"reason":"cold"},"stages":[]}

```
