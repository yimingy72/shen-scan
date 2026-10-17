# Nmap service adapter

P0 uses the system Nmap executable (`NMAP_BINARY`, default `nmap`). Install the distribution's `nmap` package, including its `nmap-service-probes` data. Do not copy only the executable without data files. Keep the complete distribution data directory (normally `/usr/share/nmap`), particularly `nmap-service-probes`, `nmap-services` and `nmap-protocols`, together with package license notices. Record the installed `nmap --version` with the deployment; reproducing a run requires a compatible tool/data installation.

The Agent invokes one process at a time per worker. Each batch contains at most 32 already discovered ports from one pinned IPv4 address, avoiding cross-host port-list expansion:

```text
nmap -sT -sV --version-light -Pn -n --max-retries 1 --max-parallelism 4 --host-timeout 90s -p <discovered-ports> -oX - <pinned-ip>
```

`--max-parallelism` bounds Nmap service object concurrency for supported versions; it is not an exact application request rate limit. No NSE scripts or OS discovery are enabled. Nmap's default version-detection exclusion for raw printer port 9100 remains; excluded endpoints are explicitly incomplete, not identified, and do not trigger HTTP fallback. This does not reduce Masscan's TCP 1–65535 discovery coverage.

The XML parser streams completed port elements, accounts for every assigned endpoint, and preserves completed results when the remaining output is truncated or the host deadline expires. A service name based only on the port-number table is `unknown`. Probed HTTP/TLS-Web and unknown endpoints are candidates for the one-way Web stage. Nmap success with omitted endpoints never counts those endpoints as identified.

Run the optional installed-tool check only against its in-process loopback HTTP fixture:

```sh
SCAN_NMAP_INTEGRATION=1 go test ./internal/agent -run TestNmapLoopbackHTTP -count=1 -v
```

Sources: [version detection](https://nmap.org/book/man-version-detection.html), [XML output](https://nmap.org/book/man-output.html), [Nmap license](https://nmap.org/npsl/). Nmap is distributed under its own Nmap Public Source License; the system package retains its notices.
