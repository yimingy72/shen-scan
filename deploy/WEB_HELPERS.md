# Web helpers

P0 packages two Go subprocesses separately from the Agent so scanner SDK dependencies and matcher memory do not enter the heartbeat process. Both helper modules use `replace scanplatform => ../..`; build them inside this repository. The web module requires Go 1.26 or Go's automatic toolchain support.

```sh
(cd cmd/web-probe-worker && go build -o ../../bin/web-probe-worker .)
(cd cmd/fingerprint-worker && go build -tags passive_only -o ../../bin/fingerprint-worker .)
```

`deploy/build-release.sh` cross-compiles both for Linux amd64. The bootstrap installs the helpers and the distribution's complete Nmap package/data. For prebuilt Worker images, install these at image-build time and retain the version/data records. Nmap is not bundled by copying a lone executable; see [Nmap adapter](nmap/README.md).

- `web-probe-worker`: httpx v1.12.0 request/title SDK and WappalyzerGo v0.2.96. The HTTP transport is explicitly bounded and uses the assigned connect IP, Host and SNI. This is not a wrapper around all of httpx CLI or `httpx.Do`: the checked SDK lacks the transport hook and independent decoding bounds needed by this profile. No automatic crawler, browser, redirect following or generic active template runner is enabled.
- `fingerprint-worker`: fingers engine commit `e870395e8984`, built with `passive_only`, persistent passive matching over Fingers, FingerprintHub and EHole. Legacy tasks retain the embedded data digest. New external data bundles are prepared and checked by this same fixed engine, addressed by SHA-256, and pinned when a task is created. Updating source data does not replace an in-flight task's data or upgrade the SDK. Per-engine evidence is retained before product display merging; unsupported and active rules are counted separately. See [bundle contract and deployment](../docs/FINGERPRINT_BUNDLES.md).
- `internal/webevidence` defines bounded JSONL/envelope identities. Large responses are capped during reads/decoding; missing and partial evidence remain explicit. The Agent terminates subprocess groups on cancellation.

P1 requires `request_admission=loopback-v1` and `stream_protocol=jsonl-item-v1` in the Web helper capability response before sending an entry. The Agent reuses a sequential helper process with per-entry IDs and deadlines; cancellation or identity errors kill and reap it before reuse. Each actual request, including alternate schemes and icons, asks the Agent's tokenized loopback callback for shared admission after TLS and before HTTP writes. The callback carries no control credential. A parsed Wappalyzer snapshot is cached by exact digest within the existing size bound; replacing the snapshot replaces this single cache entry.

The PoC execution scope is unchanged. A task must explicitly enable PoC, and product matching selects applicable checks. Nuclei receives existing supported templates; unsupported negative completion cannot be inferred from process exit alone.

Primary components and licenses: [httpx (MIT)](https://github.com/projectdiscovery/httpx/blob/v1.12.0/LICENSE.md), [WappalyzerGo (MIT)](https://github.com/projectdiscovery/wappalyzergo/blob/v0.2.96/LICENSE.md), [fingers source](https://github.com/chainreactors/fingers/tree/e870395e898422e43e271ec08f47ff2ccb4003ee). The checked fingers module has no top-level LICENSE file; this integration does not assign it an MIT license or establish redistribution rights. Its upstream README and any supplied notices accompany the dependency manifest. Embedded rule sources retain their respective upstream terms; do not describe a matcher library's license as a universal license for every dataset. Confirm distribution terms before publishing prebuilt helpers/rule bundles externally.
