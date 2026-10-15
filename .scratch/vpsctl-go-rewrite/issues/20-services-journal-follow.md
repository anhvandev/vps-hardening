# 20: Services — journal with live follow

**What to build:** From a Service the operator opens its journal, scrolls recent lines, and toggles live follow; leaving the view stops following.

**Blocked by:** 19

**Status:** resolved

- [x] Follow streams new lines without freezing the TUI; leaving the view terminates the stream process.
- [x] Large journals load a bounded tail, not the whole history.
- [x] Tests with scripted journal output; follow tested via a fake stream.

## Comments

Resolved on `feat/vpsctl-tui` @ c505e2b (merge). Review fixes in b136567.
