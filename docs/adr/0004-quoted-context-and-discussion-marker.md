# ADR 0004: Benign security discussion cannot become a bypass

**Status:** accepted. Spec requires security discussion as a negative class but an attacker can add
"this is about prompt injection". The discussion detector is informational only. Quoted/code context may
downgrade one level (medium/high only), only in profiles that opt in (default: `user-input`), and never to
`allow`. Measured cost: quoted attack strings are still routed to *review*.
