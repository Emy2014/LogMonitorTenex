# Observability

Structured logging, metrics and alerting for LogMonitor.

## Why

Four questions this has to answer:

| | |
|---|---|
| **Explain what went wrong** | A failed analysis should say which stage failed and for which request — without needing to reproduce it |
| **Prevent the next failure** | Latency and error-rate trends surface problems before users report them |
| **Track status and performance** | Where time actually goes: parsing, detection, or the model |
| **Visibility** | Aggregates no single request can show — success rates, p95, throughput |

## Logs vs metrics

**A log is one occurrence. A metric is an aggregate over many.**

- *"Analysis 68e0 completed in 2,841ms"* — a log line. Specific, high cardinality, answers "what happened to this one?"
- *"p95 analysis latency is 3,412ms over 512 analyses"* — a metric. Aggregate, low cardinality, answers "how is the system doing?"

You cannot compute a success rate from one log line, and you cannot debug one user's failure from a percentile. Both are needed.

---

## Logs

Every line is JSON on stdout — one object, machine-parseable, no multi-line stack traces breaking a log pipeline.

```json
{
  "ts": "2026-09-21T00:57:12.418Z",
  "level": "INFO",
  "event": "analysis.completed",
  "logger": "logmonitor.pipeline",
  "module": "pipeline", "func": "_run", "line": 158,
  "request_id": "9d4c73266b514102",
  "user_id": "u_8a26fc764e75",
  "analysis_id": "3f2a...",
  "entries": 2734, "candidates": 10, "anomalies": 10,
  "overall_risk": "critical", "ai_fallback": false,
  "duration_ms": 43.42
}
```

### The fields, and why each is there

| Field | Purpose |
|---|---|
| `level` | Severity. 5xx logs at ERROR, 4xx at WARNING, so severity alone is a useful filter |
| `event` | **Machine-readable type.** `analysis.completed`, not a sentence. Survives message rewording; dashboards and alerts key off it |
| `logger` | Hierarchy — `logmonitor.pipeline`, `logmonitor.ai`, `logmonitor.http`. Identifies the owning subsystem |
| `module`/`func`/`line` | Provenance — exactly which code emitted this |
| `request_id` | Correlation across the whole request, **including background work** |
| `user_id` | Who. Hashed — see below |
| `duration_ms` | How long |

### Correlation across background work

The analysis runs in a `BackgroundTask` *after* the HTTP response is sent. The request id is carried into it explicitly (`run_analysis(analysis_id, request_id)`), so one grep follows an upload through to its findings:

```bash
docker compose logs api | jq 'select(.request_id == "9d4c73266b514102")'
```

Without that, the trail goes cold precisely where the interesting work happens.

### Volume

One access-log line per request, not one per stage. Per-stage detail is DEBUG. A log volume nobody can afford to retain is not observability.

The health check (`/api/health`, polled every few seconds by Cloud Run) and `/api/metrics` are excluded — they would otherwise dominate both logs and metrics.

---

## Customer data never enters logs

**The most important rule here.** LogMonitor ingests customer proxy logs: usernames, internal IPs, full URLs with query strings. If that content reaches application logs, the observability pipeline becomes a second, less-guarded copy of the customer's data. For a security product this is the thing a reviewer probes hardest.

**Log identifiers and counts, never content.**

Where a value must be correlatable, log a salted hash:

```python
hash_identifier(user.id, prefix="u_")   # -> "u_8a26fc764e75"
```

Stable within a deployment, so correlation works; useless outside it. Salted because a rainbow table over a small domain — six usernames, RFC1918 addresses — is otherwise trivial.

`app/observability/redaction.py` also strips a forbidden-field list (`raw`, `url`, `username`, `client_ip`, `host`, `user_agent`, …) inside the formatter. That is a backstop, not the primary defence: call sites are expected not to pass them. It exists so a careless future edit fails safe.

Enforced by test, not by discipline — `test_no_customer_data_in_logs` uploads the suspicious sample and asserts that no seeded username, hostname, device name, URL path or `10.12.0.0/16` address appears anywhere in the logs.

---

## Metrics

`GET /api/metrics` — **authenticated**. Metrics expose traffic shape, error rates and usage volume; not something to leave open on a public URL, even with no customer data in it.

### Instruments

**Counters** — monotonic totals, by label
`http.requests{route,method,status}` · `http.errors` · `uploads.total` · `uploads.bytes` · `analyses.total{outcome}` · `anomalies.detected{kind,severity}` · `llm.calls{outcome}` · `llm.tokens{direction}`

**Histograms** — distributions, reported as p50/p95/p99/min/max/mean
`http.latency_ms{route}` · `upload.parse_ms` · `analysis.total_ms` · `pipeline.stage_ms{stage}` · `llm.latency_ms`

**Gauges** — point-in-time
`process.cpu_percent` · `process.memory_mb` · `analyses.in_flight`

**Derived** — ratios that only exist as aggregates
`http_success_rate` · `http_error_rate` · `analysis_success_rate` · `llm_success_rate` · `llm_fallback_rate`

### Per-stage timing is the point

```
pipeline.stage_ms:
  load       p50=22.560
  detect     p50=19.033
  evidence   p50= 1.348
  persist    p50= 0.234
  llm        p50= 0.179     <- fallback path; a real API call is ~2-8s
```

"Analysis took 3s" does not tell you whether to optimise the detectors or the model call. These five numbers do.

### Label cardinality

Metrics are labelled by **route template**, never concrete path:

```
/api/analyses/{analysis_id}          ✅  eight label values, forever
/api/analyses/68e090d1-584f-...      ❌  a new label value per analysis
```

Unbounded label cardinality is the standard way to melt a metrics backend.

### Deliberate limitations

- **Per-process and in-memory.** With several Cloud Run instances, each reports its own view; values reset when an instance stops. A real deployment ships to a central store.
- **Bounded history** — 512 samples per histogram series. A percentile over an unbounded buffer is a memory leak with extra steps.
- **Hand-rolled rather than `prometheus-client`** — ~150 readable lines, true percentiles from retained samples rather than approximations from pre-declared buckets, and no scrape server needed to see anything. Prometheus or OpenTelemetry is the production answer.

---

## Alerting

Evaluated every 60 seconds; emits structured `alert.firing` / `alert.resolved` events.

| Alert | Default | Rationale |
|---|---|---|
| `http_latency_p95` | > 5000 ms | User-visible slowness |
| `http_error_rate` | > 5% | Requests failing |
| `cpu_high` | > 85% | Saturation before it becomes latency |
| `llm_fallback_rate` | > 20% | **Product regression, not infrastructure** — findings shipping without explanations |

Two properties that matter more than the thresholds:

- **Minimum sample count** (20). A p95 over three requests is noise.
- **Fires on transitions, not every evaluation.** Re-logging the same breach every 60 seconds trains people to ignore alerts.

Thresholds are defaults in `app/config.py` and need tuning against real traffic before they are trustworthy.

On GCP these events become log-based alerting policies in Cloud Monitoring. Real delivery — PagerDuty, Slack, email — is out of scope.

---

## Model accuracy

**Online, there is no ground truth.** Nothing tells a running system whether a flagged anomaly was a real attack, so accuracy cannot be a live metric. Anyone who puts "model accuracy" on a production dashboard is measuring something else.

Split it in two:

### Offline — real accuracy

`scripts/measure_accuracy.py`. The sample generator seeds known attacks, which makes the sample files a labelled dataset.

```
  recall    100%   (6/6 attack classes)
  precision 100%   (0 false-positive classes on benign)
  F1        1.00
```

Exits non-zero on regression, so it runs in CI. This is what catches a detector-tuning change that quietly stops finding data exfiltration.

### Online — proxy signals

What a live system can actually watch, all in `/api/metrics`:

- `llm_fallback_rate` — the model stage degrading
- `llm.calls{outcome=refusal}` — safety classifier declining (real for security content)
- `llm.calls{outcome=parse_failed}` — schema validation failing
- candidate→anomaly ratio — the model discarding what detectors flag
- `anomalies.detected{kind}` distribution — a detector going silent or noisy

None is accuracy. All of them move when accuracy breaks.

---

## Not implemented, and why

| | |
|---|---|
| **Cache hit rate** | There is no cache. Reporting one would be inventing a number. |
| **Network bandwidth** | A platform metric, not observable in-process. Cloud Run reports it. |
| **Distributed tracing** | A real gap. `request_id` gives most of the practical benefit; OpenTelemetry is the proper answer. |
| **Alert delivery** | Events are emitted; routing to PagerDuty/Slack is out of scope. |
| **Log shipping and retention** | stdout only. Cloud Run forwards to Cloud Logging. |
| **Metric persistence** | Resets on restart. |
| **Frontend RUM** | Backend only. |

---

## Trying it

```bash
docker compose up -d
# log in, upload samples/zscaler_suspicious.log, then:

docker compose logs api | jq 'select(.event | startswith("analysis"))'
docker compose logs api | jq 'select(.request_id == "<id>")'   # follow one request
curl -b cookies.txt localhost:3000/api/metrics | jq .derived
python3 scripts/measure_accuracy.py
```

Set `LOG_JSON=false` for readable local logs.
