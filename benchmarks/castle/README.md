# CASTLE benchmark artifacts

The corpus itself remains in the external benchmark cache and is never tracked
here. This directory contains source-free result records only.

`results/analyzer-control-stratified-pilot.json` is the first repeated pilot:
five real analyzer-generation runs over one seeded case per in-scope CWE. It
records candidate and corpus hashes for every repetition and explicitly limits
its inference to deterministic harness repeatability. It contains no model
calls and is not evidence about Gemini variance or enhancement quality.
