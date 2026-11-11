# Security boundaries

This is a trusted-operator CLI, not a multi-tenant URL-fetching service. Only supply the origin of a changedetection.io instance you control or are permitted to read. Authentication is read from `CHANGEDETECTION_API_KEY`; never include real keys in fixtures, reports, screenshots or issues.

The client rejects credential-bearing URLs, non-root paths, fragments, query strings, private/link-local addresses and unsafe DNS answers. Explicit local mode admits only loopback addresses. DNS is checked for each request and the connected address is pinned. There are no redirects, ambient proxies or TLS bypass options. A fixed socket timeout limits stalled socket operations, but DNS resolution follows OS timing and a slow peer can extend the total operation time. Run the CLI within an outer job deadline if an absolute wall-clock limit is needed.

Watch IDs and timestamps are validated before constructing API paths. Only GET is implemented. Response bodies and input files are byte-bounded, decoded as UTF-8 and normalized as text; HTML is not executed. The viewer treats JSON strings as text.

Default report evidence omits raw snapshots, origin, UUID and API key. Line hashes still reveal equality and may permit guessing low-entropy text. Snapshot timestamps may be sensitive. `--include-diff` deliberately adds raw changed text. Ignore rules can hide important changes. No anonymity or complete PII-redaction guarantee is made.

Report vulnerabilities using synthetic reproductions; never open an issue containing a real key or a private monitored page.
