# Workspace — CaMeL to CTL translation

Source files:
- CaMeL: [`src/camel/pipeline_elements/security_policies/workspace.py`](../../src/camel/pipeline_elements/security_policies/workspace.py)
- CTL:   [`src/camel/ext/ctl_policies/workspace.py`](../../src/camel/ext/ctl_policies/workspace.py)

## Status

| CaMeL policy                      | CTL translation       | Notes                                                                              |
|-----------------------------------|-----------------------|------------------------------------------------------------------------------------|
| `send_email`                      | partial (W1)          | Recipient trusted check translated; reader-set check on body/subject out of scope. |
| `delete_email`                    | done (W2)             | CaMeL policy has inverted logic (bug); W2 implements the intended behaviour.       |
| `create_calendar_event`           | partial (W3)          | Trusted-participants clause translated; reader-set checks on fields out of scope.  |
| `cancel_calendar_event`           | done (W4)             | Direct translation of `is_trusted(event_id)`.                                     |
| `reschedule_calendar_event`       | none          | Entirely a runtime reader-set check against `env.calendar.events[event_id]`.      |
| `add_calendar_event_participants` | done (W5)             | CaMeL code checks `event_id`; W5 also checks `participants` per comment intent.   |
| `create_file`                     | no property needed    | CaMeL always allows — file only visible to owner until explicitly shared.          |
| `delete_file`                     | done (W6)             | Direct translation of `is_trusted(file_id)`.                                      |
| `share_file`                      | done (W7)             | Direct translation of `is_trusted(email)`.                                        |
| `append_to_file`                  | none          | Runtime reader-set check out of scope;|

## Per-policy detail

### `send_email`

 CaMeL checks `is_trusted(recipients ∪ cc ∪ bcc)`,
then reader-set checks on body, subject, and file attachments.

CTL W1: `AG(call_send_email -> recipients_trusted)` — primary recipients only.

### `delete_email` — CaMeL bug

CaMeL ([workspace.py:122-132](../../src/camel/pipeline_elements/security_policies/workspace.py#L122-L132)):

```python
if is_trusted(email_id):
    return Denied("Email to be deleted does not come directly from user")
return Allowed()
```

This is **inverted**. The rationale says "email_id should come from an email
requested by the user directly", which means trusted email_ids should be
*allowed*, not denied. The correct logic should be:

```python
if not is_trusted(email_id):
    return Denied(...)
return Allowed()
```

CTL W2: `AG(call_delete_email -> email_id_trusted)` implements the intended
behaviour. 

### `create_calendar_event`

CaMeL: if `is_trusted(participants)` → allow, else check reader> sets for all
event fields (title, description, location, start_time, end_time) against
the participants set.

CTL W3: `AG(call_create_calendar_event -> participants_trusted)` — translates
the trusted-participants shortcut. The reader-set fallback is out of scope.

### `cancel_calendar_event`

CaMeL: `if not is_trusted(event_id): deny`.

CTL W4: `AG(call_cancel_calendar_event -> event_id_trusted)` — exact translation. ✓

### `reschedule_calendar_event`

CaMeL looks up event participants at runtime via
`self._env.calendar.events[event_id]` and performs a reader-set check on
`new_start_time` and `new_end_time`. Entirely runtime-environment-dependent.
No CTL counterpart. Left to CaMeL's runtime enforcement.

### `add_calendar_event_participants` 
CaMeL ([workspace.py:204-217](../../src/camel/pipeline_elements/security_policies/workspace.py#L204-L217)):
```
comment: "Participants should be specified by the user"
code: if not is_trusted(event_id): deny
```

The comment describes checking `participants`; the code checks `event_id`.
CTL W5 satisfies both: `AG(call_add_calendar_event_participants -> (event_id_trusted & participants_trusted))`.

### `create_file`

CaMeL always allows. Rationale: a newly created file is only visible to
the owner until `share_file` is called. 

### `delete_file`

CaMeL: `if not is_trusted(file_id): deny`.

CTL W6: `AG(call_delete_file -> file_id_trusted)` 

### `share_file`

CaMeL: `if not is_trusted(email): deny`.

CTL W7: `AG(call_share_file -> email_trusted)` 

### `append_to_file`

CaMeL looks up file readers from `self._env.cloud_drive.files[file_id]`
and checks whether `content` is readable by them. Entirely
runtime-environment-dependent.


## Summary

Of ten CaMeL policies in the workspace suite, **five are cleanly translated**
(`cancel_calendar_event` W4, `delete_file` W6, `share_file` W7, and
`add_calendar_event_participants` W5 extending CaMeL's intent), **three
are partial** (`send_email` W1, `create_calendar_event` W3,
`append_to_file` W8).

## Policy Comparison Table

<table>
<thead>
<tr>
<th>CaMeL policy name</th>
<th>Overlap type</th>
<th>CaMeL policy implementation</th>
<th>CTL code of the same rule</th>
</tr>
</thead>
<tbody>
<tr>
<td><code>send_email</code></td>
<td>partial 1/2<br>Reader-set checks on body, subject, and attachments are runtime-only and not modelled.</td>
<td><pre><code>if is_trusted(recipients ∪ cc ∪ bcc):
    return Allowed()
if not can_readers_read_value(recipients_set, body):
    return Denied(...)
if not can_readers_read_value(recipients_set, subject):
    return Denied(...)
if not can_readers_read_value(recipients_set, attachments):
    return Denied(...)
return Allowed()</code></pre></td>
<td><pre><code>name="trusted_email_recipients",
formula="AG(call_send_email -> recipients_trusted)",
</code></pre></td>
</tr>
<tr>
<td><code>delete_email</code></td>
<td>1/1<br>CaMeL bug: logic is inverted — denies when <code>is_trusted(email_id)</code> is True. CTL implements the intended behaviour.</td>
<td><pre><code>email_id = kwargs["email_id"]
if is_trusted(email_id):
    return Denied("Email to be deleted does not come directly from user")
return Allowed()
# bug: condition is inverted</code></pre></td>
<td><pre><code>name="trusted_delete_email_id",
formula="AG(call_delete_email -> email_id_trusted)",
</code></pre></td>
</tr>
<tr>
<td><code>create_calendar_event</code></td>
<td>partial 1/2<br>Trusted-participants shortcut translated; reader-set fallback on title/description/location/times is runtime-only.</td>
<td><pre><code>participants = kwargs["participants"]
if is_trusted(participants):
    return Allowed()
if not can_readers_read_value(participants_set, kwargs["title"]):
    return Denied(...)
# ... similar checks for description, location,
#     start_time, end_time
return Allowed()</code></pre></td>
<td><pre><code>name="trusted_calendar_participants",
formula="AG(call_create_calendar_event -> participants_trusted)",
</code></pre></td>
</tr>
<tr>
<td><code>cancel_calendar_event</code></td>
<td>1/1</td>
<td><pre><code>event_id = kwargs["event_id"]
if not is_trusted(event_id):
    return Denied("Event to be deleted does not come directly from user")
return Allowed()</code></pre></td>
<td><pre><code>name="trusted_cancel_event_id",
formula="AG(call_cancel_calendar_event -> event_id_trusted)",
</code></pre></td>
</tr>
<tr>
<td><code>reschedule_calendar_event</code></td>
<td>none<br>Entirely a runtime reader-set check against <code>env.calendar.events[event_id]</code>. Left to CaMeL.</td>
<td><pre><code>event_participants = set(
    self._env.calendar.events[event_id].participants
)
if not can_readers_read_value(event_participants, new_start_time):
    return Denied(...)
if not can_readers_read_value(event_participants, new_end_time):
    return Denied(...)
return Allowed()</code></pre></td>
<td>—</td>
</tr>
<tr>
<td><code>add_calendar_event_participants</code></td>
<td>1/1<br>CaMeL code checks <code>event_id</code>; comment says "participants should be specified by the user". CTL checks both.</td>
<td><pre><code>event_id = kwargs["event_id"]
if not is_trusted(event_id):
    return Denied("Event to be deleted does not come directly from user")
return Allowed()
# comment intent: also check participants</code></pre></td>
<td><pre><code>name="trusted_add_participants",
formula=(
    "AG(call_add_calendar_event_participants -> "
    "(event_id_trusted & participants_trusted))"
),
</code></pre></td>
</tr>
<tr>
<td><code>create_file</code></td>
<td>no property needed<br>CaMeL always allows — file is only visible to its owner until <code>share_file</code> is called.</td>
<td><pre><code>return Allowed()</code></pre></td>
<td>—</td>
</tr>
<tr>
<td><code>delete_file</code></td>
<td>1/1</td>
<td><pre><code>file_id = kwargs["file_id"]
if not is_trusted(file_id):
    return Denied("File ID to be deleted does not come directly from user")
return Allowed()</code></pre></td>
<td><pre><code>name="trusted_delete_file_id",
formula="AG(call_delete_file -> file_id_trusted)",
</code></pre></td>
</tr>
<tr>
<td><code>share_file</code></td>
<td>1/1</td>
<td><pre><code>email = kwargs["email"]
if not is_trusted(email):
    return Denied("Email to share the document with does not come directly from user")
return Allowed()</code></pre></td>
<td><pre><code>name="trusted_share_file_email",
formula="AG(call_share_file -> email_trusted)",
</code></pre></td>
</tr>
<tr>
<td><code>append_to_file</code></td>
<td>None<br>CaMeL checks runtime file readers from <code>env.cloud_drive</code></td>
<td><pre><code>file_readers = set(
    self._env.cloud_drive.files[file_id].shared_with.keys()
)
if not can_readers_read_value(file_readers, kwargs["content"]):
    return Denied(...)
return Allowed()</code></pre></td>
<td><pre><code>-</code></pre></td>
</tr>
</tbody>
</table>

## Read-only tool taint comparison

CTL taints every output of any tool in [`READ_ONLY_TOOLS`](../../src/camel/ext/ctl_policies/workspace.py#L77-L92) via [`state_machine.py:131-134`](../../src/camel/ext/state_machine.py#L131-L134) (read-tool detection: [`L440-L449`](../../src/camel/ext/state_machine.py#L440-L449)). CaMeL assigns per-value capabilities in [`agentdojo_function.py:_get_metadata_for_ad`](../../src/camel/pipeline_elements/agentdojo_function.py#L120-L203).

| Tool | CTL taint | CaMeL taint | Security Overlap | Confidentiality Overlap |
|---|---|---|---|---|
| `get_unread_emails`, `get_sent_emails`, `get_received_emails`, `get_draft_emails`, `search_emails` | Always tainted ([`workspace.py:78-82`](../../src/camel/ext/ctl_policies/workspace.py#L78-L82)) | List of `Email`. Each email dispatched to `_get_email_metadata` ([`agentdojo_function.py:61-65`](../../src/camel/pipeline_elements/agentdojo_function.py#L61-L65), dispatched at [`L194-L195`](../../src/camel/pipeline_elements/agentdojo_function.py#L194-L195)): source = transformed sender (`User` if Emma else email — untrusted otherwise), readers = `{sender} ∪ recipients ∪ cc ∪ bcc`. | partial — CTL always taints; CaMeL trusts emails sent by Emma but taints externally-sent ones | none — CaMeL readers = `{sender} ∪ recipients ∪ cc ∪ bcc` (restricted); CTL has no reader model |
| `search_contacts_by_name`, `search_contacts_by_email` | Always tainted ([`workspace.py:83-84`](../../src/camel/ext/ctl_policies/workspace.py#L83-L84)) | List of `EmailContact`. `_get_email_contact_metadata` ([`agentdojo_function.py:68-71`](../../src/camel/pipeline_elements/agentdojo_function.py#L68-L71), dispatched at [`L196-L197`](../../src/camel/pipeline_elements/agentdojo_function.py#L196-L197)): source = transformed `{email}` (User if Emma, else untrusted email), readers = `Public`. | partial — CTL always taints; CaMeL trusts contacts whose email is Emma's | full — CaMeL readers = `Public`; CTL aligns |
| `get_current_day` | Trusted ([`workspace.py:97`](../../src/camel/ext/ctl_policies/workspace.py#L85)) | `str` matches [`agentdojo_function.py:131-138`](../../src/camel/pipeline_elements/agentdojo_function.py#L131-L138) → **trusted**, `Public`. A date string can't carry a prompt injection.| full — both trusted | full — CaMeL = `Public`; CTL aligns |
| `search_calendar_events`, `get_day_calendar_events` | Always tainted ([`workspace.py:86-87`](../../src/camel/ext/ctl_policies/workspace.py#L86-L87)) | List of `CalendarEvent`. `_get_calendar_event_metadata` ([`agentdojo_function.py:40-48`](../../src/camel/pipeline_elements/agentdojo_function.py#L40-L48), dispatched at [`L190-L191`](../../src/camel/pipeline_elements/agentdojo_function.py#L190-L191)): source = transformed participants (`User` if Emma, else untrusted), readers = `participants`. | partial — CTL always taints; CaMeL computes per-event trust from participants | none — CaMeL readers = `participants` (restricted); CTL has no reader model |
| `search_files_by_filename`, `get_file_by_id`, `list_files`, `search_files` | Always tainted ([`workspace.py:88-91`](../../src/camel/ext/ctl_policies/workspace.py#L88-L91)) | List of `CloudDriveFile`. `_get_cloud_drive_file_metadata` ([`agentdojo_function.py:51-58`](../../src/camel/pipeline_elements/agentdojo_function.py#L51-L58), dispatched at [`L192-L193`](../../src/camel/pipeline_elements/agentdojo_function.py#L192-L193)): source = transformed `{owner} ∪ rw-editors` (untrusted unless all are User), readers = `shared_with`. | partial — CTL always taints; CaMeL could trust files owned/edited exclusively by Emma, but in practice files typically have external editors | none — CaMeL readers = `shared_with` (restricted); CTL has no reader model |
