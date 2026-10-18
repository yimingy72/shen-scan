# Web helpers

P0 packages two Go subprocesses separately from the Agent so scanner SDK dependencies and matcher memory do not enter the heartbeat process. Both helper modules use `replace scanplatform => ../..`; build them inside this repository. The web module requires Go 1.26 or Go's automatic toolchain support.

```sh
(cd cmd/web-probe-worker && go build -o ../../bin/web-probe-worker .)
(cd cmd/fingerprint-worker && go build -o ../../bin/fingerprint-worker .)
```

`deploy/build-release.sh` cross-compiles both for Linux amd64. The bootstrap installs the helpers and the distribution's complete Nmap package/data. Optional Chrome is installed separately from Google's signed apt source by the [browser installer](browser/README.md); the release contains no browser package, and browser setup failure does not prevent ordinary scanning. For prebuilt Worker images, install these at image-build time and retain the version/data records. Nmap is not bundled by copying a lone executable; see [Nmap adapter](nmap/README.md).

- `web-probe-worker`: full profile 使用 httpx v1.12.0 完整官方 Runner（New/RunEnumeration/Close）和 WappalyzerGo v0.2.96。窄范围源码适配在 `third_party/httpx/SHEN_PATCHES.md`，加入官方传输包装、父 context、固定连接 IP 与 favicon 身份透传。普通采集默认不启用浏览器、unsafe、ZTLS 或 HTTP2 探针。任务可单独选择 JS/DOM 与截图，由系统 Chrome 子任务采集；截图复用 httpx SDK 原生截图实现，未选择与不完整执行分别记录。
- `fingerprint-worker`: fingers commit `e870395e8984`，新构建不带 `passive_only`。完整 HTTP 资源覆盖 Fingers/FPHub/EHole/Goby/favicon；主动执行原 finger/template，不改写为平台 native 规则。旧 v1 外部包与 `--legacy-embedded` 保持旧被动范围。来源数据更新采用实际编译检查，失败保留旧包。
- `internal/webevidence` defines bounded JSONL/envelope identities. Large responses are capped during reads/decoding; missing and partial evidence remain explicit. The Agent terminates subprocess groups on cancellation.

P1 requires `request_admission=loopback-v2` and `stream_protocol=jsonl-item-v1` in the Web helper capability response before sending an entry. Each Agent owns a lazy pool of up to `HTTPX_MAX_PROCESSES` sequential helpers (default 2), retaining per-entry IDs and deadlines. Cancellation or identity errors kill and reap that process before reuse without cancelling its siblings. Each actual request, including alternate schemes and icons, obtains shared admission through the Agent's tokenized loopback callback before opening the target connection; admission is checked again after TLS and before HTTP writes. An expired grant can trigger one short non-queueing refresh; otherwise the unwritten connection is closed before waiting again. Queue time and target network time are separate. The callback carries no control credential and reports its own wait duration so the helper does not deduct queue time twice. Each helper caches one bounded Wappalyzer snapshot by exact digest.

The PoC execution scope is unchanged. A task must explicitly enable PoC, and product matching selects applicable checks. Nuclei receives existing supported templates; unsupported negative completion cannot be inferred from process exit alone.

## Legacy frozen enrichment capability

以下只适用于旧任务。新建任务使用 `web-full-v2`，详见 [当前实施方案](../docs/HTTP_FINGERPRINT_FULL_IMPLEMENTATION.md)。旧内置 151 + 6 条 native HTTP 规则已退役；以下六条补采描述仅解释历史快照。

`bounded-enrichment-v1` is an additional capability, not a replacement for `profile=bounded-passive-v1`, `request_admission=loopback-v2` or `stream_protocol=jsonl-item-v1`. The helper advertises `enrichment_profile=bounded-enrichment-v1`; the Agent declares `web_enrichment_profile` in claim only after discovering that exact capability. Legacy run snapshots pin it and HTTP payloads, including service-derived work, and checks it on claim replay. Upgrade the controller first, then idle Workers with matching Agent/helper components. An incapable Worker can still perform compatible stages, but cannot claim enriched HTTP work.

| Frozen HTTP payload | Behavior with the current helper |
|---|---|
| No `web_enrichment_profile` | Original passive collection, existing same-port scheme confirmation and icons; no redirect following or product collection |
| `web_enrichment_profile=bounded-enrichment-v1` | At most 3 strictly same-origin redirect hops and candidate-bound HTTP collection |

Installing the new binaries does not opt old snapshots into enrichment. New profile support must not be inferred merely from the unchanged passive profile or binary name.

Enrichment keeps one 90-second parent deadline per executing entry. Primary work, alternate scheme confirmation, redirects, icons and supplements share at most 8 logical collect attempts. Each helper collect carries a stable `request_seq` to the Agent loopback callback; TLS grant refresh still obtains fresh shared admission but does not consume another logical operation. This count is not a count of successful responses or a wire RPS guarantee.

Each followed redirect must retain scheme, exact hostname, effective port and the pinned connect IP. Cross-origin destinations are recorded without fetching them. Collection selects at most 64 candidate rules and can fetch at most 2 additional distinct URLs; a supplemental operation is one exact GET with no redirect, alternate scheme or icon collection. Same-URL rules share the response, and already complete primary/icon responses may be reused. The six built-in collection definitions are explicitly selected HTTP product confirmations, separate from their source PoC entries. Rules, products, paths and source revisions are frozen in the run; they retain ordinary rule-library import/export, disable and delete controls.

Primary response bodies remain bounded at 2 MiB and icons at 256 KiB. Stored primary Probe bodies are hash-only; supplemental bodies retain at most a 32 KiB complete/prefix preview. The Agent also bounds the complete JSON observation for the 2 MiB upload batch, recording supported omission/truncation fields; a record that cannot be reduced is rejected by the common non-retryable size guard. It cannot block in an endless reduction loop. See [the execution and evidence contract](../docs/WEB_ENRICHMENT.md) for the rule list, trace fields and limits. These bounds do not establish scanner throughput or discovery completeness.

Primary components and licenses: [httpx (MIT)](https://github.com/projectdiscovery/httpx/blob/v1.12.0/LICENSE.md), [WappalyzerGo (MIT)](https://github.com/projectdiscovery/wappalyzergo/blob/v0.2.96/LICENSE.md), [fingers source](https://github.com/chainreactors/fingers/tree/e870395e898422e43e271ec08f47ff2ccb4003ee). The checked fingers module has no top-level LICENSE file; this integration does not assign it an MIT license or establish redistribution rights. Its upstream README and any supplied notices accompany the dependency manifest. Embedded rule sources retain their respective upstream terms; do not describe a matcher library's license as a universal license for every dataset. Confirm distribution terms before publishing prebuilt helpers/rule bundles externally.
