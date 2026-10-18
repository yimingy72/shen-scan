Pinned SDK overrides

The modules are source copies of github.com/chainreactors/fingers
v1.2.2-0.20260927063431-e870395e8984 and github.com/chainreactors/neutron
v0.1.1-0.20260714062907-716c6b167cb6. Upstream tests, testdata, examples,
docs and the two neutron verification executables are omitted. Licenses and
embedded resources remain. go.mod replaces only these pinned modules.

Local changes preserve original fingerprint and neutron template execution:
- strict FingerprintHub loader errors instead of silently skipping records;
- associated icon evidence for native fingers and FingerprintHub AND/OR rules;
- real HTML title extraction for EHole title rules;
- neutron regex fallback to the already pinned regexp2 dependency for extended
  PCRE constructs unsupported by Go regexp;
- whole-template IDs, controlled transport/context entry point and cancellation;
- remove unsafe URL.Path-only FingerprintHub transport cache (no shared cache);
- bounded response decoding before active evidence reaches matcher execution.

To reconstruct the exact upstream baseline, use `go mod download -json` with
those versions, copy the resulting Dir to a writable directory, omit the same
nonruntime files, and compare against this directory. No module-cache file is
modified. The source/resource versions above remain pinned for reproducibility.
