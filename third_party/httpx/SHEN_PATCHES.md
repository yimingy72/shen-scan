# Official httpx v1.12.0 source override

Upstream: github.com/projectdiscovery/httpx v1.12.0. LICENSE.md retained.
Runtime Go source is copied unchanged except:
- runner.Options and common/httpx.Options pass Context, FixedIP and WrapTransport.
- common/httpx.New passes WrapTransport to retryablehttp-go v1.3.25; original transport, fastdialer and native TLS remain.
- enumeration and favicon clones retain caller context. A selected fixed IP avoids auxiliary DNS resolution in result metadata.
- favicon host preservation follows the original logical origin rather than replacing an explicit Host override.
- `runner/headless.go` exports `ScreenshotWithBodyFromPage` from the existing native capture path. Existing CLI callers and the controlled system-Chrome adapter share WaitLoad/WaitIdle, capture and body extraction; an optional pre-capture callback lets the adapter check its size bounds. Native CLI callers pass nil and preserve their behavior.

No module cache files are patched. The worker opts into the wrapper and keeps legacy profile behavior in its own collector. HTTP2Probe, unsafe/rawhttp and ZTLS are not part of the admitted profile. Optional browser traffic uses the separate controlled browser lane; Chrome direct egress is blocked and each allowed request uses the same admission service. Browser capture is not enabled on the ordinary Runner by default.
