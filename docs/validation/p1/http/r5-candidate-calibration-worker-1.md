# R5 calibration/worker-1：完整请求与响应

验证状态：未利用，自建目标；仅认证使用占位符。校准任务在从未执行前由夹具固定4档范围，结果由真实工具产生。

记录时间：2026-10-17T21:10:32.910742+00:00
实际URL：`http://127.0.0.1:18085/api/runs/9b87bf46-ba05-4a8c-a225-8ada497995f6`

```http
GET /api/runs/9b87bf46-ba05-4a8c-a225-8ada497995f6 HTTP/1.1
Host: 127.0.0.1:18085
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 21:10:32 GMT
Content-Length: 534
Connection: close

{"id":"9b87bf46-ba05-4a8c-a225-8ada497995f6","name":"P1 real variable-work calibration","targets":["172.28.1.11"],"modes":["port"],"status":"completed","created_at":"2026-10-17T21:08:01.821561Z","updated_at":"2026-10-17T21:09:36.602911Z","task_total":6,"task_done":6,"task_failed":0,"asset_count":6,"target_count":1,"target_done":1,"open_port_count":3,"http_count":0,"input_count":1,"poc_enabled":false,"finding_count":0,"verification_finding_count":0,"check_match_count":0,"discovery_match_count":0,"poc_checked_count":0,"error":""}

```

记录时间：2026-10-17T21:10:33.149692+00:00
实际URL：`http://127.0.0.1:18085/api/runs/9b87bf46-ba05-4a8c-a225-8ada497995f6/results?&limit=200&offset=0`

```http
GET /api/runs/9b87bf46-ba05-4a8c-a225-8ada497995f6/results?&limit=200&offset=0 HTTP/1.1
Host: 127.0.0.1:18085
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 21:10:33 GMT
Content-Length: 566
Connection: close

{"items":[{"ips":["172.28.1.11"],"ports":[80,8088,9443],"state":"completed","target":"172.28.1.11","titles":[],"products":[],"services":["unknown"],"task_done":6,"http_count":0,"open_flood":false,"port_state":"completed","task_total":6,"updated_at":"2026-10-18T05:09:36.602911+08:00","error_count":0,"task_failed":0,"technologies":[],"port_coverage":"complete","failure_reason":"","open_port_count":3,"fingerprint_count":3,"fingerprint_limited":false}],"summary":{"http_endpoints":0,"limited_targets":0,"open_ports":3,"targets":1,"targets_with_errors":0},"total":1}

```

记录时间：2026-10-17T21:10:33.438678+00:00
实际URL：`http://127.0.0.1:18085/api/runs/9b87bf46-ba05-4a8c-a225-8ada497995f6/http?status=all&&limit=200&offset=0`

```http
GET /api/runs/9b87bf46-ba05-4a8c-a225-8ada497995f6/http?status=all&&limit=200&offset=0 HTTP/1.1
Host: 127.0.0.1:18085
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 21:10:33 GMT
Content-Length: 23
Connection: close

{"items":[],"total":0}

```

记录时间：2026-10-17T21:10:33.679210+00:00
实际URL：`http://127.0.0.1:18085/api/scheduler/status`

```http
GET /api/scheduler/status HTTP/1.1
Host: 127.0.0.1:18085
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 21:10:33 GMT
Content-Length: 387
Connection: close

{"http_budget":{"active_connect_ips":1,"admission_burst":1,"cluster_rps":250,"enforcement":"cooperative_request_admission","per_connect_ip_rps":10,"permit_lifetime_ms":500,"unexpired_permit_receipts":0},"port_batch":{"size":4,"samples":0,"reason":"cold"},"port_range":"1-65535","service_batch":{"size":7,"samples":8,"seconds_per_item":6.159386510681153,"reason":"observed"},"stages":[]}

```
