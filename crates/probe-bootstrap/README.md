# Probe Bootstrap

`enoki-probe-bootstrap` is the separately distributed, minimal trust entry for
Probe installation. It is not a member of a Probe Asset Bundle and must never
link the long-running Probe, collectors, runtime, or upgrader.

`acquire` is non-root and writes a bounded, length-prefixed verified handoff to
stdout. The only elevated entry point is `activate-stdin`: it accepts no path
or destination argument, writes the stream into a root-private exclusive
temporary file, and verifies the complete trust chain again before activation.
