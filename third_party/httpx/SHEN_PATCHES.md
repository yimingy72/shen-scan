# Official httpx v1.12.0 source override

Upstream: github.com/projectdiscovery/httpx v1.12.0. LICENSE.md retained.
Runtime Go source is copied unchanged except:
- runner.Options and common/httpx.Options pass Context, FixedIP and WrapTransport.
- common/httpx.New passes WrapTransport to retryablehttp-go v1.3.25; original transport, fastdialer and native TLS remain.
- enumeration and favicon clones retain caller context. A selected fixed IP avoids auxiliary DNS resolution in result metadata.
- favicon host preservation follows the original logical origin rather than replacing an explicit Host override.

No module cache files are patched. The worker opts into the wrapper and keeps legacy profile behavior in its own collector. HTTP2Probe, unsafe/rawhttp, ZTLS and browser traffic are not part of the admitted profile.
