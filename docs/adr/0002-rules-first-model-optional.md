# ADR 0002: Rule-first core; classifier optional

**Status:** accepted. The core is deterministic, offline, CPU-only and explainable. A classifier is an
optional detector behind an adapter (offline by default, timeout, graceful degradation). Reasons: licensing
of guard-model weights (e.g. Llama 4 Community License, gated), reproducibility, latency, and avoiding a
single opaque model as the product. Consequence: recall on paraphrases is limited until a model (or more
data) is added and benchmarked.
