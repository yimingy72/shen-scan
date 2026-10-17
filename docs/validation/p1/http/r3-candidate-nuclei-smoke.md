# R3 candidate nuclei-smoke：完整请求与响应

验证状态：未利用，自建夹具；Bearer认证值占位，报文内容未截断。

记录时间：2026-10-17T20:16:11.363594+00:00
实际URL：`http://127.0.0.1:18083/api/library`

```http
POST /api/library HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}
Content-Type: application/json
Content-Length: 289

{"id": "p1-cloud-synthetic-product", "kind": "http", "name": "P1 synthetic fixture product marker", "engine": "native", "severity": "info", "enabled": true, "definition": {"product": "P1CloudSyntheticFixture", "matchers": [{"part": "body", "type": "word", "words": ["p1-cloud-fixture"]}]}}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:11 GMT
Content-Length: 298
Connection: close

{"id":"p1-cloud-synthetic-product","kind":"http","name":"P1 synthetic fixture product marker","engine":"native","severity":"info","enabled":true,"builtin":false,"revision":1,"definition":{"product":"P1CloudSyntheticFixture","matchers":[{"part":"body","type":"word","words":["p1-cloud-fixture"]}]}}

```

记录时间：2026-10-17T20:16:12.115384+00:00
实际URL：`http://127.0.0.1:18083/api/library/import`

```http
POST /api/library/import HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}
Content-Type: application/json
Content-Length: 422

{"format": "nuclei", "execution_profile": "http-basic-v1", "content": "id: p1-cloud-batch-negative\ninfo:\n  name: P1 harmless synthetic fixture negative\n  author: shen-validation\n  severity: info\n  metadata:\n    product: P1CloudSyntheticFixture\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/p1-batch\"]\n    matchers:\n      - type: word\n        part: body\n        words: [\"p1-cloud-never-present-marker\"]\n"}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:12 GMT
Content-Length: 1058
Connection: close

{"count":1,"items":[{"id":"nuclei-p1-cloud-batch-negative-575501c5","kind":"poc","purpose":"check","name":"P1 harmless synthetic fixture negative","engine":"nuclei","severity":"info","enabled":false,"builtin":false,"revision":1,"applies_to":["P1CloudSyntheticFixture"],"nuclei":{"template_id":"p1-cloud-batch-negative","execution_profile":"http-basic-v1","content_sha256":"575501c5413c219a8d077dcfc2b76844f9468588c447fe945c7e3dedabde5ff2","protocols":["http"],"info":{"author":"shen-validation","metadata":{"product":"P1CloudSyntheticFixture"},"name":"P1 harmless synthetic fixture negative","severity":"info"},"request_count":1},"source":"Imported original Nuclei HTTP YAML","definition":{},"template":"id: p1-cloud-batch-negative\ninfo:\n  name: P1 harmless synthetic fixture negative\n  author: shen-validation\n  severity: info\n  metadata:\n    product: P1CloudSyntheticFixture\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/p1-batch\"]\n    matchers:\n      - type: word\n        part: body\n        words: [\"p1-cloud-never-present-marker\"]\n"}]}

```

记录时间：2026-10-17T20:16:19.230129+00:00
实际URL：`http://127.0.0.1:18083/api/library/nuclei-p1-cloud-batch-positive-688fb06c`

```http
PATCH /api/library/nuclei-p1-cloud-batch-positive-688fb06c HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}
Content-Type: application/json
Content-Length: 42

{"enabled": false, "expected_revision": 2}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:19 GMT
Content-Length: 1023
Connection: close

{"id":"nuclei-p1-cloud-batch-positive-688fb06c","kind":"poc","purpose":"check","name":"P1 harmless synthetic fixture positive","engine":"nuclei","severity":"info","enabled":false,"builtin":false,"revision":3,"applies_to":["P1CloudSyntheticFixture"],"nuclei":{"template_id":"p1-cloud-batch-positive","execution_profile":"http-basic-v1","content_sha256":"688fb06caf6fe8e49aef45c27acc6dce2dd73b38e01f6b83c51f5bc53d65a14e","protocols":["http"],"info":{"name":"P1 harmless synthetic fixture positive","author":"shen-validation","metadata":{"product":"P1CloudSyntheticFixture"},"severity":"info"},"request_count":1},"source":"Imported original Nuclei HTTP YAML","definition":{},"template":"id: p1-cloud-batch-positive\ninfo:\n  name: P1 harmless synthetic fixture positive\n  author: shen-validation\n  severity: info\n  metadata:\n    product: P1CloudSyntheticFixture\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/p1-batch\"]\n    matchers:\n      - type: word\n        part: body\n        words: [\"p1-cloud-fixture\"]\n"}

```

记录时间：2026-10-17T20:16:19.717885+00:00
实际URL：`http://127.0.0.1:18083/api/library/nuclei-p1-cloud-batch-negative-575501c5`

```http
PATCH /api/library/nuclei-p1-cloud-batch-negative-575501c5 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}
Content-Type: application/json
Content-Length: 42

{"enabled": false, "expected_revision": 2}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:19 GMT
Content-Length: 1036
Connection: close

{"id":"nuclei-p1-cloud-batch-negative-575501c5","kind":"poc","purpose":"check","name":"P1 harmless synthetic fixture negative","engine":"nuclei","severity":"info","enabled":false,"builtin":false,"revision":3,"applies_to":["P1CloudSyntheticFixture"],"nuclei":{"template_id":"p1-cloud-batch-negative","execution_profile":"http-basic-v1","content_sha256":"575501c5413c219a8d077dcfc2b76844f9468588c447fe945c7e3dedabde5ff2","protocols":["http"],"info":{"name":"P1 harmless synthetic fixture negative","author":"shen-validation","metadata":{"product":"P1CloudSyntheticFixture"},"severity":"info"},"request_count":1},"source":"Imported original Nuclei HTTP YAML","definition":{},"template":"id: p1-cloud-batch-negative\ninfo:\n  name: P1 harmless synthetic fixture negative\n  author: shen-validation\n  severity: info\n  metadata:\n    product: P1CloudSyntheticFixture\nhttp:\n  - method: GET\n    path: [\"{{BaseURL}}/p1-batch\"]\n    matchers:\n      - type: word\n        part: body\n        words: [\"p1-cloud-never-present-marker\"]\n"}

```

记录时间：2026-10-17T20:16:12.629569+00:00
实际URL：`http://127.0.0.1:18083/api/runs`

```http
POST /api/runs HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}
Content-Type: application/json
Content-Length: 226

{"name": "P1 harmless Linux Nuclei batch", "targets": ["http://172.28.1.1:8088/"], "modes": ["http"], "poc_enabled": true, "poc_rule_ids": ["nuclei-p1-cloud-batch-positive-688fb06c", "nuclei-p1-cloud-batch-negative-575501c5"]}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:12 GMT
Content-Length: 540
Connection: close

{"id":"34fe77b3-353d-456a-a687-b43a3d5a5f38","name":"P1 harmless Linux Nuclei batch","targets":["http://172.28.1.1:8088/"],"modes":["http"],"status":"pending","created_at":"2026-10-17T20:16:12.655104Z","updated_at":"2026-10-17T20:16:12.655104Z","task_total":1,"task_done":0,"task_failed":0,"asset_count":0,"target_count":1,"target_done":0,"open_port_count":0,"http_count":0,"input_count":1,"poc_enabled":true,"finding_count":0,"verification_finding_count":0,"check_match_count":0,"discovery_match_count":0,"poc_checked_count":0,"error":""}

```

记录时间：2026-10-17T20:16:21.423364+00:00
实际URL：`http://127.0.0.1:18083/api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38`

```http
GET /api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:21 GMT
Content-Length: 542
Connection: close

{"id":"34fe77b3-353d-456a-a687-b43a3d5a5f38","name":"P1 harmless Linux Nuclei batch","targets":["http://172.28.1.1:8088/"],"modes":["http"],"status":"completed","created_at":"2026-10-17T20:16:12.655104Z","updated_at":"2026-10-17T20:16:13.286533Z","task_total":2,"task_done":2,"task_failed":0,"asset_count":3,"target_count":1,"target_done":1,"open_port_count":0,"http_count":1,"input_count":1,"poc_enabled":true,"finding_count":1,"verification_finding_count":0,"check_match_count":1,"discovery_match_count":0,"poc_checked_count":2,"error":""}

```

记录时间：2026-10-17T20:16:15.390524+00:00
实际URL：`http://127.0.0.1:18083/api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38/findings?status=all`

```http
GET /api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38/findings?status=all HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:15 GMT
Connection: close
Transfer-Encoding: chunked

{"items":[{"id":"b8096596-ce37-4e69-9144-6d988e109931","ip":"","url":"http://172.28.1.1:8088/p1-batch","kind":"poc","port":8088,"engine":"nuclei","run_id":"34fe77b3-353d-456a-a687-b43a3d5a5f38","target":"http://172.28.1.1:8088/","purpose":"check","rule_id":"nuclei-p1-cloud-batch-positive-688fb06c","evidence":"nuclei matcher status matched; JSONL: {\"template\":\"01.yaml\",\"template-id\":\"p1-cloud-batch-positive\",\"template-path\":\"/tmp/scanplatform-nuclei-batch-877024461/templates/01.yaml\",\"template-encoded\":\"aWQ6IHAxLWNsb3VkLWJhdGNoLXBvc2l0aXZlCmluZm86CiAgbmFtZTogUDEgaGFybWxlc3Mgc3ludGhldGljIGZpeHR1cmUgcG9zaXRpdmUKICBhdXRob3I6IHNoZW4tdmFsaWRhdGlvbgogIHNldmVyaXR5OiBpbmZvCiAgbWV0YWRhdGE6CiAgICBwcm9kdWN0OiBQMUNsb3VkU3ludGhldGljRml4dHVyZQpodHRwOgogIC0gbWV0aG9kOiBHRVQKICAgIHBhdGg6IFsie3tCYXNlVVJMfX0vcDEtYmF0Y2giXQogICAgbWF0Y2hlcnM6CiAgICAgIC0gdHlwZTogd29yZAogICAgICAgIHBhcnQ6IGJvZHkKICAgICAgICB3b3JkczogWyJwMS1jbG91ZC1maXh0dXJlIl0K\",\"info\":{\"name\":\"P1 harmless synthetic fixture positive\",\"author\":[\"shen-validation\"],\"tags\":null,\"severity\":\"info\",\"metadata\":{\"product\":\"P1CloudSyntheticFixture\"}},\"type\":\"http\",\"host\":\"172.28.1.1\",\"port\":\"8088\",\"scheme\":\"http\",\"url\":\"http://172.28.1.1:8088\",\"matched-at\":\"http://172.28.1.1:8088/p1-batch\",\"request\":\"GET /p1-batch HTTP/1.1\\r\\nHost: 172.28.1.1:8088\\r\\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15\\r\\nAccept: */*\\r\\nAccept-Language: en\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n\",\"response\":\"HTTP/1.1 200 OK\\r\\nContent-Length: 104\\r\\nContent-Type: text/html; charset=utf-8\\r\\nDate: Sat, 17 Oct 2026 20:16:13 GMT\\r\\nServer: P1SyntheticFixture/1.0 Python/3.10.12\\r\\nX-P1-Synthetic-Fixture: true\\r\\n\\r\\n\\u003c!doctype html\\u003e\\u003ctitle\\u003eP1 synthetic fixture\\u003c/title\\u003e\\u003ch1\\u003eSelf-built test target\\u003c/h1\\u003e\\u003cp\\u003ep1-cloud-fixture\\u003c/p\\u003e\",\"ip\":\"172.28.1.1\",\"timestamp\":\"2026-10-18T04:16:13.279626579+08:00\",\"curl-command\":\"curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15' 'http://172.28.1.1:8088/p1-batch'\",\"matcher-status\":true}","protocol":"http","severity":"info","rule_name":"P1 harmless synthetic fixture positive","observed_at":"2026-10-18T04:16:13.280354+08:00","template_id":"p1-cloud-batch-positive","rule_revision":2,"source_target":"172.28.1.1","content_sha256":"688fb06caf6fe8e49aef45c27acc6dce2dd73b38e01f6b83c51f5bc53d65a14e","engine_version":"3.11.1","finding_status":"matched","trigger_reason":"http_technology","evidence_profile":"nuclei-3.11.1-single-http-response-v1","matched_products":["P1CloudSyntheticFixture"],"execution_profile":"http-basic-v1"},{"id":"e7efbdc2-8afe-4cb2-85e9-cf8ff1ac65f5","ip":"","url":"http://172.28.1.1:8088/p1-batch","kind":"poc","port":8088,"engine":"nuclei","run_id":"34fe77b3-353d-456a-a687-b43a3d5a5f38","target":"http://172.28.1.1:8088/","purpose":"check","rule_id":"nuclei-p1-cloud-batch-negative-575501c5","evidence":"nuclei completed the scoped read-only request; matchers did not match; JSONL: {\"template\":\"00.yaml\",\"template-id\":\"p1-cloud-batch-negative\",\"template-path\":\"/tmp/scanplatform-nuclei-batch-877024461/templates/00.yaml\",\"info\":{\"name\":\"P1 harmless synthetic fixture negative\",\"author\":[\"shen-validation\"],\"tags\":null,\"severity\":\"info\",\"metadata\":{\"product\":\"P1CloudSyntheticFixture\"}},\"type\":\"http\",\"host\":\"172.28.1.1\",\"port\":\"8088\",\"scheme\":\"http\",\"url\":\"http://172.28.1.1:8088\",\"request\":\"GET /p1-batch HTTP/1.1\\r\\nHost: 172.28.1.1:8088\\r\\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10.15, rv:140.0) Gecko/20100101 Firefox/140.0\\r\\nAccept: */*\\r\\nAccept-Language: en\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n\",\"response\":\"HTTP/1.1 200 OK\\r\\nContent-Length: 104\\r\\nContent-Type: text/html; charset=utf-8\\r\\nDate: Sat, 17 Oct 2026 20:16:13 GMT\\r\\nServer: P1SyntheticFixture/1.0 Python/3.10.12\\r\\nX-P1-Synthetic-Fixture: true\\r\\n\\r\\n\\u003c!doctype html\\u003e\\u003ctitle\\u003eP1 synthetic fixture\\u003c/title\\u003e\\u003ch1\\u003eSelf-built test target\\u003c/h1\\u003e\\u003cp\\u003ep1-cloud-fixture\\u003c/p\\u003e\",\"ip\":\"172.28.1.1\",\"timestamp\":\"2026-10-18T04:16:13.173218035+08:00\",\"matcher-status\":false}","protocol":"http","severity":"info","rule_name":"P1 harmless synthetic fixture negative","observed_at":"2026-10-18T04:16:13.179417+08:00","template_id":"p1-cloud-batch-negative","rule_revision":2,"source_target":"172.28.1.1","content_sha256":"575501c5413c219a8d077dcfc2b76844f9468588c447fe945c7e3dedabde5ff2","engine_version":"3.11.1","finding_status":"not_matched","trigger_reason":"http_technology","evidence_profile":"nuclei-3.11.1-single-http-response-v1","matched_products":["P1CloudSyntheticFixture"],"execution_profile":"http-basic-v1","can_prove_no_match":true}],"summary":{"check_matched":1,"discovery_matched":0,"error":0,"incomplete":0,"matched":1,"not_matched":1,"verification_matched":0},"total":2}

```

记录时间：2026-10-17T20:16:15.665883+00:00
实际URL：`http://127.0.0.1:18083/api/observations/b8096596-ce37-4e69-9144-6d988e109931`

```http
GET /api/observations/b8096596-ce37-4e69-9144-6d988e109931 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:15 GMT
Connection: close
Transfer-Encoding: chunked

{"id":"b8096596-ce37-4e69-9144-6d988e109931","run_id":"34fe77b3-353d-456a-a687-b43a3d5a5f38","observed_at":"2026-10-18T04:16:13.280354+08:00","kind":"poc","target":"http://172.28.1.1:8088/","ip":"","port":8088,"protocol":"http","url":"http://172.28.1.1:8088/p1-batch","request_raw":"GET /p1-batch HTTP/1.1\r\nHost: 172.28.1.1:8088\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n","response_raw":"HTTP/1.1 200 OK\r\nContent-Length: 104\r\nContent-Type: text/html; charset=utf-8\r\nDate: Sat, 17 Oct 2026 20:16:13 GMT\r\nServer: P1SyntheticFixture/1.0 Python/3.10.12\r\nX-P1-Synthetic-Fixture: true\r\n\r\n\u003c!doctype html\u003e\u003ctitle\u003eP1 synthetic fixture\u003c/title\u003e\u003ch1\u003eSelf-built test target\u003c/h1\u003e\u003cp\u003ep1-cloud-fixture\u003c/p\u003e","rule_id":"nuclei-p1-cloud-batch-positive-688fb06c","rule_name":"P1 harmless synthetic fixture positive","rule_revision":2,"template_id":"p1-cloud-batch-positive","execution_profile":"http-basic-v1","content_sha256":"688fb06caf6fe8e49aef45c27acc6dce2dd73b38e01f6b83c51f5bc53d65a14e","engine":"nuclei","severity":"info","finding_status":"matched","engine_version":"3.11.1","evidence_profile":"nuclei-3.11.1-single-http-response-v1","evidence":"nuclei matcher status matched; JSONL: {\"template\":\"01.yaml\",\"template-id\":\"p1-cloud-batch-positive\",\"template-path\":\"/tmp/scanplatform-nuclei-batch-877024461/templates/01.yaml\",\"template-encoded\":\"aWQ6IHAxLWNsb3VkLWJhdGNoLXBvc2l0aXZlCmluZm86CiAgbmFtZTogUDEgaGFybWxlc3Mgc3ludGhldGljIGZpeHR1cmUgcG9zaXRpdmUKICBhdXRob3I6IHNoZW4tdmFsaWRhdGlvbgogIHNldmVyaXR5OiBpbmZvCiAgbWV0YWRhdGE6CiAgICBwcm9kdWN0OiBQMUNsb3VkU3ludGhldGljRml4dHVyZQpodHRwOgogIC0gbWV0aG9kOiBHRVQKICAgIHBhdGg6IFsie3tCYXNlVVJMfX0vcDEtYmF0Y2giXQogICAgbWF0Y2hlcnM6CiAgICAgIC0gdHlwZTogd29yZAogICAgICAgIHBhcnQ6IGJvZHkKICAgICAgICB3b3JkczogWyJwMS1jbG91ZC1maXh0dXJlIl0K\",\"info\":{\"name\":\"P1 harmless synthetic fixture positive\",\"author\":[\"shen-validation\"],\"tags\":null,\"severity\":\"info\",\"metadata\":{\"product\":\"P1CloudSyntheticFixture\"}},\"type\":\"http\",\"host\":\"172.28.1.1\",\"port\":\"8088\",\"scheme\":\"http\",\"url\":\"http://172.28.1.1:8088\",\"matched-at\":\"http://172.28.1.1:8088/p1-batch\",\"request\":\"GET /p1-batch HTTP/1.1\\r\\nHost: 172.28.1.1:8088\\r\\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15\\r\\nAccept: */*\\r\\nAccept-Language: en\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n\",\"response\":\"HTTP/1.1 200 OK\\r\\nContent-Length: 104\\r\\nContent-Type: text/html; charset=utf-8\\r\\nDate: Sat, 17 Oct 2026 20:16:13 GMT\\r\\nServer: P1SyntheticFixture/1.0 Python/3.10.12\\r\\nX-P1-Synthetic-Fixture: true\\r\\n\\r\\n\\u003c!doctype html\\u003e\\u003ctitle\\u003eP1 synthetic fixture\\u003c/title\\u003e\\u003ch1\\u003eSelf-built test target\\u003c/h1\\u003e\\u003cp\\u003ep1-cloud-fixture\\u003c/p\\u003e\",\"ip\":\"172.28.1.1\",\"timestamp\":\"2026-10-18T04:16:13.279626579+08:00\",\"curl-command\":\"curl -X 'GET' -d '' -H 'Accept: */*' -H 'Accept-Language: en' -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Safari/605.1.15' 'http://172.28.1.1:8088/p1-batch'\",\"matcher-status\":true}","purpose":"check","matched_products":["P1CloudSyntheticFixture"],"trigger_reason":"http_technology"}

```

记录时间：2026-10-17T20:16:16.300847+00:00
实际URL：`http://127.0.0.1:18083/api/observations/e7efbdc2-8afe-4cb2-85e9-cf8ff1ac65f5`

```http
GET /api/observations/e7efbdc2-8afe-4cb2-85e9-cf8ff1ac65f5 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:16 GMT
Connection: close
Transfer-Encoding: chunked

{"id":"e7efbdc2-8afe-4cb2-85e9-cf8ff1ac65f5","run_id":"34fe77b3-353d-456a-a687-b43a3d5a5f38","observed_at":"2026-10-18T04:16:13.179417+08:00","kind":"poc","target":"http://172.28.1.1:8088/","ip":"","port":8088,"protocol":"http","url":"http://172.28.1.1:8088/p1-batch","request_raw":"GET /p1-batch HTTP/1.1\r\nHost: 172.28.1.1:8088\r\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10.15, rv:140.0) Gecko/20100101 Firefox/140.0\r\nAccept: */*\r\nAccept-Language: en\r\nAccept-Encoding: gzip\r\n\r\n","response_raw":"HTTP/1.1 200 OK\r\nContent-Length: 104\r\nContent-Type: text/html; charset=utf-8\r\nDate: Sat, 17 Oct 2026 20:16:13 GMT\r\nServer: P1SyntheticFixture/1.0 Python/3.10.12\r\nX-P1-Synthetic-Fixture: true\r\n\r\n\u003c!doctype html\u003e\u003ctitle\u003eP1 synthetic fixture\u003c/title\u003e\u003ch1\u003eSelf-built test target\u003c/h1\u003e\u003cp\u003ep1-cloud-fixture\u003c/p\u003e","rule_id":"nuclei-p1-cloud-batch-negative-575501c5","rule_name":"P1 harmless synthetic fixture negative","rule_revision":2,"template_id":"p1-cloud-batch-negative","execution_profile":"http-basic-v1","content_sha256":"575501c5413c219a8d077dcfc2b76844f9468588c447fe945c7e3dedabde5ff2","engine":"nuclei","severity":"info","finding_status":"not_matched","engine_version":"3.11.1","evidence_profile":"nuclei-3.11.1-single-http-response-v1","can_prove_no_match":true,"evidence":"nuclei completed the scoped read-only request; matchers did not match; JSONL: {\"template\":\"00.yaml\",\"template-id\":\"p1-cloud-batch-negative\",\"template-path\":\"/tmp/scanplatform-nuclei-batch-877024461/templates/00.yaml\",\"info\":{\"name\":\"P1 harmless synthetic fixture negative\",\"author\":[\"shen-validation\"],\"tags\":null,\"severity\":\"info\",\"metadata\":{\"product\":\"P1CloudSyntheticFixture\"}},\"type\":\"http\",\"host\":\"172.28.1.1\",\"port\":\"8088\",\"scheme\":\"http\",\"url\":\"http://172.28.1.1:8088\",\"request\":\"GET /p1-batch HTTP/1.1\\r\\nHost: 172.28.1.1:8088\\r\\nUser-Agent: Mozilla/5.0 (Macintosh, Intel Mac OS X 10.15, rv:140.0) Gecko/20100101 Firefox/140.0\\r\\nAccept: */*\\r\\nAccept-Language: en\\r\\nAccept-Encoding: gzip\\r\\n\\r\\n\",\"response\":\"HTTP/1.1 200 OK\\r\\nContent-Length: 104\\r\\nContent-Type: text/html; charset=utf-8\\r\\nDate: Sat, 17 Oct 2026 20:16:13 GMT\\r\\nServer: P1SyntheticFixture/1.0 Python/3.10.12\\r\\nX-P1-Synthetic-Fixture: true\\r\\n\\r\\n\\u003c!doctype html\\u003e\\u003ctitle\\u003eP1 synthetic fixture\\u003c/title\\u003e\\u003ch1\\u003eSelf-built test target\\u003c/h1\\u003e\\u003cp\\u003ep1-cloud-fixture\\u003c/p\\u003e\",\"ip\":\"172.28.1.1\",\"timestamp\":\"2026-10-18T04:16:13.173218035+08:00\",\"matcher-status\":false}","purpose":"check","matched_products":["P1CloudSyntheticFixture"],"trigger_reason":"http_technology"}

```

记录时间：2026-10-17T20:16:18.797501+00:00
实际URL：`http://127.0.0.1:18083/api/library/p1-cloud-synthetic-product`

```http
PATCH /api/library/p1-cloud-synthetic-product HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}
Content-Type: application/json
Content-Length: 42

{"enabled": false, "expected_revision": 1}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:18 GMT
Content-Length: 299
Connection: close

{"id":"p1-cloud-synthetic-product","kind":"http","name":"P1 synthetic fixture product marker","engine":"native","severity":"info","enabled":false,"builtin":false,"revision":2,"definition":{"product":"P1CloudSyntheticFixture","matchers":[{"part":"body","type":"word","words":["p1-cloud-fixture"]}]}}

```

记录时间：2026-10-17T20:16:21.675714+00:00
实际URL：`http://127.0.0.1:18083/api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38/results?&limit=200&offset=0`

```http
GET /api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38/results?&limit=200&offset=0 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:21 GMT
Content-Length: 640
Connection: close

{"items":[{"ips":["172.28.1.1"],"ports":[],"state":"completed","target":"172.28.1.1","titles":["P1 synthetic fixture"],"products":["P1SyntheticFixture/1.0 Python/3.10.12"],"services":["http"],"task_done":2,"http_count":1,"open_flood":false,"port_state":"not_scanned","task_total":2,"updated_at":"2026-10-18T04:16:13.286533+08:00","error_count":0,"task_failed":0,"technologies":["P1CloudSyntheticFixture"],"port_coverage":"not_scanned","failure_reason":"","open_port_count":0,"fingerprint_count":0,"fingerprint_limited":false}],"summary":{"http_endpoints":1,"limited_targets":0,"open_ports":0,"targets":1,"targets_with_errors":0},"total":1}

```

记录时间：2026-10-17T20:16:21.991827+00:00
实际URL：`http://127.0.0.1:18083/api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38/http?status=all&&limit=200&offset=0`

```http
GET /api/runs/34fe77b3-353d-456a-a687-b43a3d5a5f38/http?status=all&&limit=200&offset=0 HTTP/1.1
Host: 127.0.0.1:18083
Accept: application/json
Accept-Encoding: identity
Connection: close
Authorization: Bearer ${TEST_ADMIN_TOKEN}


```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: Sat, 17 Oct 2026 20:16:21 GMT
Connection: close
Transfer-Encoding: chunked

{"items":[{"id":"a8d35051-99a7-4423-b5fe-24c244e648f4","ip":"172.28.1.1","url":"http://172.28.1.1:8088/","kind":"http","port":8088,"title":"P1 synthetic fixture","engine":"httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96","server":"P1SyntheticFixture/1.0 Python/3.10.12","target":"http://172.28.1.1:8088/","outcome":"identified","coverage":"complete","evidence":"{\"probe\":{\"id\":\"82280a35a544fea3e3147afa4b73aa3c\",\"protocol\":\"shen-web-v1\",\"engine\":\"httpx-sdk-v1.12.0/bounded-transport+wappalyzergo-v0.2.96\",\"profile\":\"bounded-passive-v1\",\"response\":{\"url\":\"http://172.28.1.1:8088/\",\"connect_ip\":\"172.28.1.1\",\"host\":\"172.28.1.1:8088\",\"observed_at\":\"2026-10-17T20:16:12.838130998Z\",\"status_code\":200,\"proto\":\"HTTP/1.1\",\"headers\":{\"Content-Length\":[\"104\"],\"Content-Type\":[\"text/html; charset=utf-8\"],\"Date\":[\"Sat, 17 Oct 2026 20:16:12 GMT\"],\"Server\":[\"P1SyntheticFixture/1.0 Python/3.10.12\"],\"X-P1-Synthetic-Fixture\":[\"true\"]},\"request_raw\":\"GET / HTTP/1.1\\r\\nHost: 172.28.1.1:8088\\r\\nUser-Agent: shen-scan/2\\r\\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\\r\\nAccept-Charset: utf-8\\r\\nAccept-Encoding: identity\\r\\n\\r\\n\",\"header_raw\":\"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: 104\\r\\nContent-Type: text/html; charset=utf-8\\r\\nDate: Sat, 17 Oct 2026 20:16:12 GMT\\r\\nServer: P1SyntheticFixture/1.0 Python/3.10.12\\r\\nX-P1-Synthetic-Fixture: true\\r\\n\\r\\n\",\"body_storage\":\"hash_only\",\"body_sha256\":\"f239b1522aea1585ab14ff28f83b60caae4c8ae7b4eda2c18422aed8504357aa\",\"encoded_bytes\":104,\"decoded_bytes\":104,\"completeness\":\"full\"},\"attempts\":[{\"url\":\"http://172.28.1.1:8088/\",\"connect_ip\":\"172.28.1.1\",\"host\":\"172.28.1.1:8088\",\"observed_at\":\"2026-10-17T20:16:12.838130998Z\",\"status_code\":200,\"proto\":\"HTTP/1.1\",\"headers\":{\"Content-Length\":[\"104\"],\"Content-Type\":[\"text/html; charset=utf-8\"],\"Date\":[\"Sat, 17 Oct 2026 20:16:12 GMT\"],\"Server\":[\"P1SyntheticFixture/1.0 Python/3.10.12\"],\"X-P1-Synthetic-Fixture\":[\"true\"]},\"request_raw\":\"GET / HTTP/1.1\\r\\nHost: 172.28.1.1:8088\\r\\nUser-Agent: shen-scan/2\\r\\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\\r\\nAccept-Charset: utf-8\\r\\nAccept-Encoding: identity\\r\\n\\r\\n\",\"header_raw\":\"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: 104\\r\\nContent-Type: text/html; charset=utf-8\\r\\nDate: Sat, 17 Oct 2026 20:16:12 GMT\\r\\nServer: P1SyntheticFixture/1.0 Python/3.10.12\\r\\nX-P1-Synthetic-Fixture: true\\r\\n\\r\\n\",\"body_storage\":\"hash_only\",\"body_sha256\":\"f239b1522aea1585ab14ff28f83b60caae4c8ae7b4eda2c18422aed8504357aa\",\"encoded_bytes\":104,\"decoded_bytes\":104,\"completeness\":\"full\"}],\"icons\":[{\"url\":\"http://172.28.1.1:8088/favicon.ico\",\"connect_ip\":\"172.28.1.1\",\"host\":\"172.28.1.1:8088\",\"observed_at\":\"2026-10-17T20:16:12.846012501Z\",\"status_code\":200,\"proto\":\"HTTP/1.1\",\"headers\":{\"Content-Length\":[\"104\"],\"Content-Type\":[\"text/html; charset=utf-8\"],\"Date\":[\"Sat, 17 Oct 2026 20:16:12 GMT\"],\"Server\":[\"P1SyntheticFixture/1.0 Python/3.10.12\"],\"X-P1-Synthetic-Fixture\":[\"true\"]},\"request_raw\":\"GET /favicon.ico HTTP/1.1\\r\\nHost: 172.28.1.1:8088\\r\\nUser-Agent: shen-scan/2\\r\\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\\r\\nAccept-Charset: utf-8\\r\\nAccept-Encoding: identity\\r\\n\\r\\n\",\"header_raw\":\"HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: 104\\r\\nContent-Type: text/html; charset=utf-8\\r\\nDate: Sat, 17 Oct 2026 20:16:12 GMT\\r\\nServer: P1SyntheticFixture/1.0 Python/3.10.12\\r\\nX-P1-Synthetic-Fixture: true\\r\\n\\r\\n\",\"body_storage\":\"hash_only\",\"body_sha256\":\"f239b1522aea1585ab14ff28f83b60caae4c8ae7b4eda2c18422aed8504357aa\",\"encoded_bytes\":104,\"decoded_bytes\":104,\"completeness\":\"full\"}],\"title\":\"P1 synthetic fixture\",\"cff_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"requests\":2},\"fingerprint\":{\"protocol\":\"shen-web-v1\",\"id\":\"d19210e14e354ecd9794b39dc153c01fde6a8769bf2c6bd2ddbc35a58b374246/f239b1522aea1585ab14ff28f83b60caae4c8ae7b4eda2c18422aed8504357aa\",\"bundle\":\"b5946286a877ff75a1c7b9914e9c3e4b0aba4e15287ee1cf594eef6db8e18538\"},\"assigned_fingerprint_bundle\":\"b5946286a877ff75a1c7b9914e9c3e4b0aba4e15287ee1cf594eef6db8e18538\"}","protocol":"http","work_key":"url:0:0","observed_at":"2026-10-18T04:16:12.954417+08:00","status_code":200,"technologies":[{"name":"P1CloudSyntheticFixture","rule_id":"p1-cloud-synthetic-product","evidence":"body word \"p1-cloud-fixture\" matched","rule_revision":1}],"source_target":"172.28.1.1","content_sha256":"f239b1522aea1585ab14ff28f83b60caae4c8ae7b4eda2c18422aed8504357aa","evidence_profile":"bounded-excerpt-v1","execution_profile":"bounded-passive-v1"}],"total":1}

```

记录时间：2026-10-17T20:16:22.225114+00:00
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
Date: Sat, 17 Oct 2026 20:16:22 GMT
Content-Length: 349
Connection: close

{"http_budget":{"active_connect_ips":128,"admission_burst":1,"cluster_rps":250,"enforcement":"cooperative_request_admission","per_connect_ip_rps":10,"permit_lifetime_ms":500,"unexpired_permit_receipts":0},"port_batch":{"size":4,"samples":0,"reason":"cold"},"port_range":"1-65535","service_batch":{"size":32,"samples":0,"reason":"cold"},"stages":[]}

```
