# ADR 0003: Preserve the original; analyse derived views with offset maps

**Status:** accepted. Normalization never overwrites input. Each view carries per-character offsets (or a
fixed span for decoded payloads) so evidence always points into the original. NFKC is per code point to keep
the mapping exact. Homoglyph folding is limited to mixed-script tokens. Rule matches found only in a
disguise-undoing view raise a separate `obfuscation_evasion` finding (disguise is itself a signal).
