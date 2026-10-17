# Third-party notices for fingerprint and PoC rules

Selected passive fingerprint signals in `builtin_http_expanded.go` and
`builtin_http_catalog.go` were adapted and rewritten from:

- projectdiscovery/wappalyzergo v0.3.5
- commit `10c7df1e2b381046fad03dccb3bec3280052df99`
- <https://github.com/projectdiscovery/wappalyzergo>

The adapted rules use only response headers, cookie names, and static HTML
signals that the SHEN matcher can preserve. The upstream database is not
bundled.

## MIT License

Copyright (c) 2021 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Automatically updated upstream catalogs

The control plane can download compatible rules from the fixed official sources:

- <https://github.com/projectdiscovery/wappalyzergo> (MIT).
- <https://github.com/projectdiscovery/nuclei-templates> (MIT).

The original catalogs are not bundled in the source repository. Updates retain
an exact commit SHA, content digest and the upstream license text in the database.
The rule source screen exposes the complete license. Normalized Nuclei templates
have SHEN IDs and only compatible read-only fields; obsolete upstream digest
signature comments are removed because rewriting invalidates that signature.
Other original comments and authors are retained. These rules are adapted data,
not templates whose original ProjectDiscovery signature has been verified.

### Nuclei Templates license (snapshot 17f5725dc10ced09f464dd2d255c19957aad51e7)

MIT License

Copyright (c) 2025 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
