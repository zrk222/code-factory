# Security Policy

Please report vulnerabilities privately through GitHub Security Advisories for
`zrk222/code-factory`. Do not include secrets, private customer data, or active
exploit details in a public issue.

Supported releases are the latest published minor release and the current
`main` branch. Local HMAC signatures prove verify-before-load discipline but do
not provide third-party identity; GitHub artifact attestations or a future
public-key signer are required for externally verifiable provenance.

## Local MCP HTTP

The stateless MCP HTTP listener binds to loopback and requires a bearer token
or a configured identity validator. Browser origins must match an explicitly
allowed origin exactly. For a loopback origin such as `http://localhost:PORT`,
`PORT` and `{port}` in `--allow-origin` resolve to the actual listener port.
Startup prints the expanded loopback origins.

The November 19 transport review identified three compatibility issues. A
dynamic listener port left configured Origin placeholders unresolved. Missing
request metadata shared the header-mismatch diagnostic. HTTP initialization
advertised a different protocol version from HTTP discovery and validation.
The fixes retain required metadata and exact host, origin, and bearer checks.
The review covered the local transport. Hosted runtime coverage was unavailable.
