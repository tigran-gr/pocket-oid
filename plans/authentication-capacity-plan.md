# Authentication capacity measurement plan

Status: proposed; no load tests have been run. Implementation inspected at
commit `453452d` on 2026-09-06.

Concurrent working-tree edits adding configurable ES256 signing appeared during
this review. The baseline described below uses RS256. Freeze and record the
exact snapshot before running; once the algorithm changes are complete and
verified, run RS256 and ES256 as separate configurations under identical load.

Measure the highest sustained rate of **successful completed authentications
per second** that one Pocket-OID process can serve within stated latency and
error limits. Also report HTTP requests per second. Capacity is specific to the
flow, hardware, configuration, state population, and deployment path; there is
no defensible implementation-wide RPS number before measuring these.

This measurement covers client credentials and local authentication only.
Re-authentication through upstream providers is deferred, including its load
scenarios, mock providers, dependency measurements, and traffic in mixed tests.

## 1. Benchmark the in-scope flows separately

One load-generator iteration represents one complete authentication, ending
when the expected tokens arrive and response checks pass.

| Scenario | Requests to Pocket-OID per successful iteration | Purpose |
| --- | --- | --- |
| Client credentials | 1: `POST /oauth/token` | Machine authentication and one RS256 access-token signature |
| Fresh local OIDC login, default consent | 5: `GET /authorize`, `POST /login`, `GET /authorize`, `POST /consent`, `POST /oauth/token` | Full login, new session, authorization code, access token and ID token |
| Fresh local OIDC login, consent skipped | 4: same flow without `POST /consent` | Isolate configured consent cost |
| Existing-session OIDC login | 3 with consent; 2 with consent skipped | Reuse a valid session, obtain a new code and exchange it |

For example, 100 successful fresh local logins/s with default consent generates
approximately 500 HTTP requests/s to Pocket-OID. This is an illustration, not a
capacity estimate. Exclude setup, health probes, and the relying
application's callback from the Pocket-OID request count; report them separately.

Use `openid` and S256 PKCE for the OIDC scenarios. The basic fixture currently
allows only `default`, so prepare explicit benchmark client configurations.
An authorization-code flow without `openid` issues only an access token and must
have its own label if measured. Do not extrapolate full-login capacity from
client credentials or from a benchmark of `/login` alone.

Start with client credentials and fresh local login with default consent. Add
existing-session and consent-skip scenarios, then measure the expected mix of
these in-scope flows once its proportions are known. Do not average isolated
scenario maxima to estimate mixed capacity.

## 2. Define a passing rate before testing

These are proposed initial service-level objectives, not existing requirements:

| Measurement | Client credentials | Complete local OIDC flow |
| --- | --- | --- |
| p95 client-observed duration | < 200 ms | < 500 ms |
| p99 client-observed duration | < 500 ms | < 1,000 ms |
| Failed valid authentication attempts | < 0.1% | < 0.1% |
| Dropped scheduled iterations | 0 | 0 |

Measure complete-flow duration from the first request through the final token
response, including network and connection time, without human typing or reading
time. Report successful-flow latency and failed-flow duration separately, plus
per-endpoint latency.

A passing run must also have correct identities and token claims, no crashes,
and no steadily growing backlog. Memory and latency must stabilize after the
state reaches its normal lifetime distribution. Any observed invalid token or
cross-user state mix-up invalidates the run regardless of the error percentage.
Enforce these conditions per scenario and in time windows, so a good overall
average cannot conceal degradation near the end. Use one-minute windows with
at least 1,000 attempts; lengthen the windows for low-rate tests.

Publish successful completions/s measured within the steady measurement window,
alongside scheduled, started, failed, timed-out, and unfinished attempts. Drain
in-flight work with a fixed timeout and report it separately; do not add drained
completions to the numerator for an already-ended measurement window.

## 3. Create a reproducible test environment

Build the unchanged baseline with `cargo build --release`, then start the built
binary directly using an isolated configuration directory selected by
`POCKET_OID_CONFIG_DIR`. Wait for `/readyz`. Record:

- Commit, working-tree changes, Cargo.lock hash, Rust and load-generator versions.
- CPU model, assigned cores, memory limit, OS, architecture, and Tokio worker
  configuration; record shared-host contention and container CPU limits.
- Signing algorithm and RSA key size or EC curve, token template and typical
  token sizes, scope/client/user counts,
  password representation, consent and PKCE settings, and `RUST_LOG` level.
- Connection reuse, protocol, network latency, and whether requests traverse a
  reverse proxy and TLS. Keep logging consistent, initially `RUST_LOG=info`.

Use only clients configured for local authentication in the benchmark fixtures.

Run a single server process on the intended deployment hardware with the load
generator on another machine. A same-machine smoke test is useful for developing
the harness, but label its results as local measurements. Confirm generator CPU,
memory, sockets, and network have headroom; repeat near the limit with extra
generator capacity if there is any doubt about which machine is saturated.

Measure direct HTTP first to establish process capacity, then repeat relevant
scenarios through the deployment's proxy/TLS path. Treat those as separate
results. Optional 1/2/4-core runs show scaling on the same host; do not predict
linear gains from more cores or replicas. Sessions and authorization codes are
process-local, so multi-replica flow routing requires a separate plan.

## 4. Implement an HTTP load harness

Use k6 with one complete authentication per iteration and an externally paced
arrival rate. Its `constant-arrival-rate` executor starts iterations independently
of response duration while virtual users are available, which keeps offered
load from silently shrinking when the server slows down.
See [k6 constant arrival rate](https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/constant-arrival-rate/).

Preallocate enough virtual users for the target rate and high-percentile flow
duration, with headroom. Record generator utilization and `dropped_iterations`;
drops can result from inadequate generator allocation or server slowdown and
must be diagnosed before attributing a limit to Pocket-OID.
See [k6 dropped iterations](https://grafana.com/docs/k6/latest/using-k6/scenarios/concepts/dropped-iterations/).

Implement the following behavior:

- Submit actual forms and follow each expected redirect explicitly. Parse the
  final callback URL for code and state without requesting the application URL.
  Preserve the server's hidden `return_to` values when submitting forms.
- Give each fresh login an empty cookie jar. For existing-session tests, prepare
  an explicitly managed session pool and reuse cookies intentionally; account
  separately for session renewal during long tests.
- Generate unique state, nonce, PKCE verifier, and authorization codes per flow.
  Never replay a consumed code or use a single mutable nonce shared by workers.
- Validate expected statuses, redirect destinations, state, response shape,
  token type, scope, and applicable issuer, audience, subject, expiry, and nonce
  claims. HTTP 200 alone is insufficient: invalid local credentials currently
  redisplay the login page with HTTP 200.
- Verify signatures and claims against JWKS in correctness smoke tests, and
  cryptographically verify a documented sample during load using provisioned
  generator capacity or a separate verifier. Label sampling coverage explicitly.
  Avoid logging credentials or full tokens.
- Count exactly one success or failure per attempted flow. Count HTTP errors,
  protocol errors, timeouts, and early script exits; disable automatic retries
  for the baseline. Run intentionally invalid requests separately.
- Tag metrics with fixed scenario and endpoint names, never code/state/session
  values. Export time series and a machine-readable summary, not just averages.

Use custom flow counters, failure rates, and duration trends with explicit
pass/fail thresholds. See [k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/).

Use the existing [black-box flow tests](../tests_blackbox/test_server_blackbox.py)
as protocol examples and reuse fixture-preparation concepts from
[blackbox_support.py](../tests_blackbox/blackbox_support.py). Its current
`ServerProcess` launches `cargo run --quiet` in the development profile; the
benchmark runner must launch the release binary and retain diagnostic logs.
Browser automation is unnecessary for generating protocol load.

## 5. Search for the sustainable limit

1. **Correctness smoke:** Exercise every enabled flow at 1–5 authentications/s,
   including concurrent users. Verify token signatures and expected failure
   behavior before measuring capacity.
2. **Exploratory sweep:** Warm up for 1–2 minutes, then try 10, 25, 50, 100, 200,
   400, etc. authentications/s for 2–3 minutes each until latency or errors cross
   the agreed limits. These rates are search inputs, not predictions. Stop on
   sustained overload, memory pressure, or process failure and retain evidence.
3. **Refine the boundary:** Between the last passing and first failing rates,
   test smaller steps until the gap is about 5–10%. Start each confirmation run
   from the same defined state population, warm up, and measure for 10 minutes.
   Repeat each candidate three times; report the range and the highest rate
   that passes all repetitions, plus the next failing rate and reason.
4. **State-size sensitivity:** Test fresh and existing-session workloads after
   seeding approximately 1k, 10k, and 100k live sessions, then the projected
   deployment population if different. Seed through normal HTTP and record
   session ages, preload duration, and estimated counts; seeding time must not
   silently expire the intended population. Also exercise delayed/abandoned
   authorization codes separately.
5. **Sustained validation:** Hold the candidate rate for 90–120 minutes. Sessions
   live for one hour in the current implementation, so a ten-minute test alone
   cannot establish steady fresh-login capacity. Inspect the period after
   expirations begin. If performance degrades, reduce the rate and repeat.
6. **Burst and recovery:** From a proven sustainable rate, apply a bounded
   1.5–2x burst for 30–60 seconds, then return to baseline and measure recovery,
   errors, and retained memory. Keep burst capacity separate from sustained RPS.

Short confirmation runs establish a provisional boundary; only the long test
qualifies a rate as sustained. If no state population or rate stabilizes within
the chosen constraints, report that result rather than publishing a short-run
maximum as sustainable capacity. Repeat near-boundary long tests when variability
makes the result ambiguous.

For a provisional operating target, start at 60–70% of the confirmed sustainable
limit and validate it with the expected traffic mix and bursts. That percentage
is an initial headroom policy, not a measured guarantee.

## 6. Investigate implementation-specific limits

These are hypotheses to test, not confirmed bottlenecks:

- **Signing CPU:** [handlers.rs](../src/handlers.rs), `issue_token` and
  `sign_token`, synchronously sign one JWT for client credentials and two for
  OIDC code exchange. Signing runs on the request execution path. Profile near
  saturation before proposing crypto or runtime changes.
- **Session population and locks:** [auth.rs](../src/auth.rs), `get_session`,
  takes a write lock and calls `retain` over the session map on every lookup.
  Code consumption similarly scans the authorization-code map under a write
  lock. Track latency against live state and retained map capacity.
- **One-hour accumulation:** [handlers.rs](../src/handlers.rs), `login`, creates
  a new session with a hardcoded 3,600-second TTL, even for a previously used
  username. At a sustained successful fresh-login rate R, live sessions can
  approach R × 3,600. For illustration, 100/s would produce about 360,000 live
  sessions. Do not shorten the TTL when claiming current-implementation capacity.
- **Password cost:** [users.rs](../src/users.rs) runs password verification on
  Tokio's blocking pool behind a CPU-count-based concurrency limit. The file
  provider can use Argon2id, legacy SHA-256, or development plaintext; SQLite
  requires Argon2id. Record the repository, password format, Argon2 parameters,
  and time spent queued for a verification permit. Benchmark Argon2id separately
  from legacy fixtures rather than extrapolating from their much cheaper hashes.

Collect server CPU per core, RSS, thread count, open connections/file descriptors,
network traffic, and errors throughout each run. The app currently has HTTP
tracing but no dedicated metrics endpoint. Begin with client timings and external
process monitoring. Use a separate profiled run to attribute time to signing,
map scans, and lock contention. If exact map sizes or lock timings are needed,
add optional bounded instrumentation in a follow-up and compare its overhead
against the unchanged baseline.

## 7. Implementation deliverables and final report

Proposed work, in order:

1. Add `tests_load/README.md`, fixture preparation and a release-process runner.
2. Add k6 client-credentials and local-flow scenarios with correctness checks,
   explicit cookie handling, arrival-rate controls, and result export.
3. Add resource collection, state-population preparation, and a repeatable
   sweep/confirmation/soak runner that stops its own processes on exit.
4. Produce a capacity report with environment/configuration manifest, raw
   results, latency-versus-rate and CPU/memory-over-time charts, and bottleneck
   evidence. Keep large raw outputs under ignored `target/load-results/`.

Use this result table for every tested environment; do not fill it from code
inspection:

| Flow/configuration | Confirmed auth/s | Pocket-OID HTTP req/s | p95 / p99 | Failures | State population / duration | First failing rate and cause |
| --- | --- | --- | --- | --- | --- | --- |
| To be measured | — | — | — | — | — | — |

The report should distinguish observed throughput, the highest confirmed
sustainable rate, and the proposed operating target. Include the next failing
rate as an upper bracket; if no failure was reached, report a lower bound.

Before running the benchmark, select the deployment machine/core limit, intended
mix of in-scope flows, latency objectives, and direct/proxied measurement path. Harness
development can proceed with the defaults above. Performance tests should run
on a controlled host, initially on demand; shared CI can check harness
correctness but should not define the advertised capacity.
