# How and where AI is used

*Requirement 3 of the brief asks for this to be documented clearly. This is that
document.*

## Summary

**AI does not detect the anomalies, and it does not produce the confidence
scores.** Those come from deterministic statistics. The LLM's job is to explain,
correlate and prioritise what the statistics already found, and to write the
timeline a SOC analyst reads first.

That split is deliberate. It keeps the detection reproducible and auditable, it
keeps cost bounded, and it means the product still works when the model is
unavailable.

---

## The pipeline

```
uploaded file
     │
     ▼
app/parser/zscaler.py        ZScaler NSS CSV → ParsedEntry[]        no AI
     │
     ▼
app/detection/stats.py       six detectors → Candidate[]            no AI
     │                       each carries a confidence score
     ▼
app/ai/evidence.py           candidates + aggregates → packet       no AI
     │                       (~3k tokens, hard-capped)
     ▼
app/ai/analyze.py            packet → Claude → Report               ◄── the only AI
     │
     ▼
app/pipeline.py              persist findings, map ids → rows       no AI
```

Exactly one API call is made per analysis, in `app/ai/analyze.py`.

---

## Stage 1 — statistical detection (no AI)

`app/detection/stats.py`. Six detectors, each a pure function over
`ParsedEntry[]`, each returning candidates with a confidence score in 0–1.

| Detector | What it looks for | How the score is computed |
|---|---|---|
| `volume_spike` | Unusual requests/IP/minute | robust z-score over per-(IP, minute) buckets, plus an absolute floor of 20 req/min |
| `data_exfil` | Outsized outbound transfer | robust z-score on `log10(request_size)`, aggregated per (user, host) |
| `beaconing` | Near-constant request interval | `1 − (stdev / mean)` of inter-request gaps, rescaled from 0.80–1.00 |
| `blocked_threat` | Proxy-flagged malware/phishing | deterministic — fixed 0.95 |
| `rare_destination` | Host seen by one user, ≤3 times | inverse frequency against the file's busiest host |
| `off_hours` | Sustained activity in a dead hour | how far below the median hour's volume, scaled by request count |

### Two choices worth defending

**Median + MAD, not mean + standard deviation.** Proxy log distributions are
heavy-tailed. A single 200MB upload drags a mean-based baseline up far enough to
hide itself — the outlier corrupts the very baseline meant to expose it. The
median absolute deviation is unaffected by a handful of extreme values.

MAD does collapse to zero when most observations are identical (most
`(IP, minute)` buckets hold exactly one request), so `_robust_z` falls back to
standard deviation in that case. An earlier version returned a constant that sat
*below* its own flag threshold, which silently suppressed every burst — there is
a regression test for it (`test_volume_spike_survives_zero_mad`).

**Baselines come from the uploaded file, not from fixed thresholds.** 500
requests/minute is alarming in a quiet office log and unremarkable in a busy
proxy feed. This also means there is no training data, no model artifact, and no
drift — the detector calibrates itself to whatever it is given.

**A statistical outlier is not automatically interesting.** `volume_spike` also
requires ≥20 requests in the minute. Four requests a minute can be a large
z-score in a very quiet log, and is never worth an analyst's time. Relative and
absolute tests together.

---

## Stage 2 — the LLM pass

`app/ai/analyze.py`. **Model: `claude-opus-5`.**

### What it is given

Only the evidence packet built by `app/ai/evidence.py`:

- **File overview** — entry count, time range, distinct users/IPs/hosts, action
  and category breakdowns, total bytes in/out
- **Ranked candidates** — for each: an opaque id, detector kind, the statistical
  confidence, the affected entry count, the evidence dict, and at most 3 sample
  raw lines for context

Hard-capped at 14,000 characters. If a pathological upload would exceed that,
sample lines are shed first, then whole candidates — so cost stays bounded
regardless of input.

### What it is deliberately *not* given

- **Raw logs in bulk.** 1.15MB of log becomes a 12.6KB packet — a 91× reduction,
  ~287,000 tokens down to ~3,100.
- **Database row ids.** It references candidates as `c0`, `c1`, … and the server
  maps those back to rows. **A hallucinated row id is structurally impossible**,
  not merely unlikely.

### What it returns

A Pydantic-validated `Report`, via structured outputs:

```python
class Report(BaseModel):
    summary: str                      # what an analyst reads first
    overall_risk: Literal["critical", "high", "medium", "low"]
    timeline: list[TimelineEvent]     # the brief's "summarised timeline"
    anomalies: list[AnomalyOut]       # explanation + recommendation per candidate
```

Because the schema is enforced, a malformed response fails loudly instead of
reaching the UI as partial data.

### Request settings

| Setting | Value | Why |
|---|---|---|
| `model` | `claude-opus-5` | |
| `thinking` | `{"type": "adaptive"}` | Severity is a judgement call; let it reason first. `budget_tokens` is rejected on Opus 5. |
| `output_format` | `Report` | Pydantic-validated structured output |
| `max_tokens` | 16000 | |

### The prompt

The system prompt (in `app/ai/analyze.py`) instructs the model to reference
candidates only by their given id, report only what the evidence supports, never
invent IPs/users/domains/timestamps, corroborate candidates that describe one
incident, and **say so plainly when activity looks benign rather than
manufacturing findings**.

That last instruction matters: an LLM handed a "find the threats" task will
oblige even when there is nothing there.

---

## Failure modes, and what happens

Every one degrades to `fallback_report` — a deterministic report built straight
from the statistical candidates. **Findings and confidence scores are always
preserved; only the narrative is lost.** An upload never fails because of the AI
layer.

| Failure | Detection | Result |
|---|---|---|
| No API key configured | checked before the call | fallback; UI shows an explanatory banner |
| **Safety refusal** | `stop_reason == "refusal"` | fallback; recorded on the analysis row |
| Schema validation fails | `parsed_output is None` | fallback |
| Network/API error | exception | fallback; error recorded |
| Unknown candidate id returned | validated against known ids | that anomaly dropped |

### Why the refusal check matters here specifically

A safety classifier can decline a request, and that returns **HTTP 200 with
`stop_reason: "refusal"`** — it does not raise. Without an explicit check it
looks like an empty response with no cause. This app's entire job is analysing
attack traffic, so it is exactly the kind of workload where that can happen.

---

## Cost

Measured on `samples/zscaler_suspicious.log` with `claude-opus-5`:

| | |
|---|---|
| Evidence packet | ~3,100 tokens |
| Total request (packet + system prompt + schema) | **7,612 input tokens** |
| Response | **3,728 output tokens** |
| Latency | **~46 s** (adaptive thinking) |
| Cost | **~$0.13 per analysis** |

Sending the raw log instead would be ~287,000 input tokens — roughly $1.44 per
upload in input alone, before it failed to fit in most context windows. The
stage-1/stage-2 split is what makes this affordable and bounded.

The ~46 s latency is why analysis runs as a background task and the frontend
polls: no HTTP request should stay open that long.

Token counts from each call are persisted on the `analyses` row
(`input_tokens`, `output_tokens`) and shown in the UI.

---

## If I had more time

- **Feed detector results back into scoring.** Corroboration between detectors
  (the same host flagged as both `rare_destination` and `blocked_threat`) should
  raise confidence; currently the LLM notes it in prose but it does not affect
  the number.
- **An eval set.** A handful of labelled logs plus assertions on which anomalies
  must be found, so prompt changes can be measured rather than eyeballed.
- **Cross-file baselines.** Baselines are per-upload, so a log that is *entirely*
  malicious has no clean baseline to contrast against. Historical baselines per
  environment would fix that.
- **Prompt caching** on the system prompt, if analyses ran at volume.
