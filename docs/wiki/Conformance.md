# Conformance

Conformance testing provides a quality gate for persona upgrades. A persona pack can declare a minimum test score; newer versions must meet or exceed that score to install.

## Conformance baseline

In `pack.toml`:

```toml
[conformance_baseline]
score = 0.92
bundle_hash = "sha256:..."
```

- `score` -- Minimum acceptable test score (0.0 to 1.0).
- `bundle_hash` -- SHA-256 hash of the canonical TOML serialization of the test bundle that produced the baseline.

## Test bundles

A test bundle is a `bundle.toml` file containing a set of test cases:

```toml
name = "my-persona-tests"
version = "1.0.0"

[[tests]]
id = "handles-error-case"
prompt = "The server returns a 500 error. What do you do?"
[tests.expected]
kind = "Contains"
value = "retry"
[tests.scorer]
kind = "Substring"
```

Each test case has:

- `id` -- Machine-readable identifier.
- `prompt` -- Text sent to the runner (the scenario to evaluate).
- `expected` -- Expected behavior.
- `scorer` -- How to score the response.

### Expected behaviors

| Kind | Fields | Description |
|---|---|---|
| `Contains` | `value` | Response must contain this substring |
| `Matches` | `pattern` | Response must match this regex |
| `JsonShape` | `shape` | Response parsed as JSON must equal this value exactly |
| `Custom` | `id` | Scoring delegated to a caller-provided implementation |

### Scoring strategies

| Scorer | Behavior |
|---|---|
| `Substring` | 1.0 if response contains the expected value, 0.0 otherwise |
| `Regex` | 1.0 if pattern matches, 0.0 otherwise (invalid regex also scores 0.0) |
| `ExactJson` | 1.0 if parsed JSON equals the shape exactly, 0.0 otherwise |
| `Caller` | Delegated to a `CallerScorer` trait implementation for domain-specific scoring |

The bundle score is the arithmetic mean of all individual test scores.

## Runner trait

The `Runner` trait abstracts how prompts are evaluated:

```rust
#[async_trait]
pub trait Runner {
    async fn run(&self, prompt: &str) -> Result<String, ConformanceError>;
}
```

A `MockRunner` is provided for testing with canned responses. Real runners can wrap any LLM API.

## Regression gate

When upgrading a persona, the regression gate evaluates three outcomes:

| Decision | Condition |
|---|---|
| `Pass` | New score >= baseline score AND bundle hash matches |
| `FailRegression` | New score < baseline score (reports the delta) |
| `FailBundleChanged` | Bundle hash does not match baseline (scores are not comparable) |

The process:

1. Run the test bundle against the new version.
2. Compute the average score.
3. Compare against the declared baseline score.
4. If the bundle hash changed, reject -- scores from different bundles are not comparable.
5. If the score dropped, reject with the regression delta.
6. Otherwise, pass.

## Bundle hashing

The bundle hash is the SHA-256 of the canonical TOML serialization of the test bundle. This ensures that changes to test content (reworded prompts, added tests, changed expectations) produce a different hash, preventing score comparisons across different test definitions.

## Verification

```bash
frameshift verify --persona <persona> --runner mock
```

Runs conformance checks against an installed persona and reports the score. Supports `--bundle` to specify a test bundle path, `--threshold` to set a score floor, and `--canned-response` for quick smoke tests with a fixed response.
