# Web helpers

P0 packages two Go subprocesses separately from the Agent so scanner SDK dependencies and matcher memory do not enter the heartbeat process. Both helper modules use `replace scanplatform => ../..`; build them inside this repository. The web module requires Go 1.26 or Go's automatic toolchain support.

```sh
(cd cmd/web-probe-worker && go build -o ../../bin/web-probe-worker .)
(cd cmd/fingerprint-worker && go build -tags passive_only -o ../../bin/fingerprint-worker .)
```

`deploy/build-release.sh` cross-compiles both for Linux amd64. The bootstrap installs the helpers and the distribution's complete Nmap package/data. For prebuilt Worker images, install these at image-build time and retain the version/data records. Nmap is not bundled by copying a lone executable; see [Nmap adapter](nmap/README.md).

- `web-probe-worker`: httpx v1.12.0 request/title SDK and WappalyzerGo v0.2.96. The HTTP transport is explicitly bounded and uses the assigned connect IP, Host and SNI. This is not a wrapper around all of httpx CLI or `httpx.Do`: the checked SDK lacks the transport hook and independent decoding bounds needed by this profile. No automatic crawler, browser, redirect following or generic active template runner is enabled.
- `fingerprint-worker`: fingers commit `e870395e8984`, persistent passive matching over Fingers, FingerprintHub and EHole, plus favicon data. Per-engine evidence is captured before product display merging. The embedded data bundle has a content digest and is checked before matching; changing dependencies/data requires generating the matching bundle constant and publishing compatible helpers. Existing tasks retain their dispatched bundle reference.
- `internal/webevidence` defines bounded JSONL/envelope identities. Large responses are capped during reads/decoding; missing and partial evidence remain explicit. The Agent terminates subprocess groups on cancellation.

The PoC execution scope is unchanged. A task must explicitly enable PoC, and product matching selects applicable checks. Nuclei receives existing supported templates; unsupported negative completion cannot be inferred from process exit alone.

Primary components and licenses: [httpx (MIT)](https://github.com/projectdiscovery/httpx/blob/v1.12.0/LICENSE.md), [WappalyzerGo (MIT)](https://github.com/projectdiscovery/wappalyzergo/blob/v0.2.96/LICENSE.md), [fingers source](https://github.com/chainreactors/fingers/tree/e870395e898422e43e271ec08f47ff2ccb4003ee). The checked fingers module has no top-level LICENSE file; this integration does not assign it an MIT license or establish redistribution rights. Its upstream README and any supplied notices accompany the dependency manifest. Embedded rule sources retain their respective upstream terms; do not describe a matcher library's license as a universal license for every dataset. Confirm distribution terms before publishing prebuilt helpers/rule bundles externally.
