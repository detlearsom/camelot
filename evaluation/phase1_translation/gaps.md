# Cross-suite translation gaps

(a) CaMeL expresses something CTL
cannot model, or 
(b) CTL expresses something CaMeL structurally cannot.

---

## Gaps where CaMeL covers something CTL cannot

### G1: Reader-set checks

CaMeL tracks a *reader set* for every value
-  a set of principals
(email addresses, channel members) permitted to observe that value.
`can_readers_read_value(readers, value)` checks at runtime whether the
intended recipients are a subset of the value's reader set. 

| Suite | Tool | Affected arguments |
|---|---|---|
| Slack | `send_direct_message` | `body` (second clause) |
| Slack | `send_channel_message` | `body` (entire policy) |
| Banking | `send_money` | `amount`, `subject`, `date` |
| Banking | `schedule_transaction` | `amount`, `subject`, `date` |
| Banking | `update_scheduled_transaction` | `amount`, `subject`, `date` |
| Travel | `send_email` | `body`, `subject`, `attachments` |
| Travel | `create_calendar_event` | `title`, `description`, `location`, `start_time`, `end_time` |
| Workspace | `send_email` | `body`, `subject`, `attachments` |
| Workspace | `create_calendar_event` | `title`, `description`, `location`, `start_time`, `end_time` |
| Workspace | `reschedule_calendar_event` | `new_start_time`, `new_end_time` (entire policy) |
| Workspace | `append_to_file` | `content` (entire policy) |


### G2: `is_public` capability flag

**Affects:** Slack suite only.

CaMeL tracks an `is_public` capability bit on values.`post_webpage` and `get_webpage` use this to check
that URLs and content are publicly shareable. 

| Tool | Affected arguments |
|---|---|
| `post_webpage` | `url`, `content` |
| `get_webpage` | `url` |


### G3: Runtime environment lookups

**Affects:** Workspace suite.

Two workspace policies fetch live state from the runtime environment
before performing their checks:

- `reschedule_calendar_event` — looks up `self._env.calendar.events[event_id].participants`
- `append_to_file` — looks up `self._env.cloud_drive.files[file_id].shared_with`


### G4 : `TrustedToolSource` in CaMeL's `is_trusted`

**Affects:** all suites, all `_trusted` propositions.

CaMeL's `is_trusted` accepts values whose source is in
`{User, CaMeL, Assistant, TrustedToolSource}`. CTL's `_trusted`
proposition fires when provenance ∈ `{trusted, user}` — it marks all
external tool outputs as `untrusted`, even those CaMeL would accept via
`TrustedToolSource`.

---

## What CTL covers that CaMeL cannot

### G5: Temporal ordering (pre-execution, all paths)

CaMeL evaluates a policy predicate at a single tool invocation. It has
no mechanism to express "tool X must have been called before tool Y on
every execution path." 

Examples already written (Slack S1–S3, email-agent P1–P5):

- `A[!call_send_direct_message U (read_channel_messages_called | read_inbox_called | get_webpage_called)]`
- `A[!call_send_email U get_contacts_called]`
- `AG(call_invite_user_to_slack -> get_webpage_called)`

These catch attacks where an attacker-controlled value is a *trusted
literal* — hardcoded by a prompt-injected P-LLM — so CaMeL sees no
taint but the ordering obligation is violated.

### G6: Liveness (EF: eventually)

CaMeL has no notion of progress obligations. A plan that silently
exits without taking a required action passes all CaMeL predicates
vacuously (no tool call → no policy check triggered). 

This is the Tier 2 liveness claim.

### G7: Static, pre-execution verification

CaMeL enforces policies at runtime as each tool call fires. CTL verifies
the entire plan before any tool is executed. This means:

- Violations on branches the LLM happened not to take are still caught.
- Plans can be rejected (and repaired) before any side effects occur.
- The counterexample trace guides the LLM repair loop with full plan
  context rather than a runtime error at a single call site.
