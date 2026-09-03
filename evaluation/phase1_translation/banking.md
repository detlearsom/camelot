# Banking — CaMeL to CTL translation

Source files:
- CaMeL: [`src/camel/pipeline_elements/security_policies/banking.py`](../../src/camel/pipeline_elements/security_policies/banking.py)
- CTL:   [`src/camel/ext/ctl_policies/banking.py`](../../src/camel/ext/ctl_policies/banking.py)

## Status

| CaMeL policy                     | CTL translation              | Notes                                                                      |
|----------------------------------|------------------------------|----------------------------------------------------------------------------|
| `send_money`                     | partial (B1 + B2)            | Recipient check direct; reader-set check approximated as `!_tainted`.      |
| `schedule_transaction`           | partial (B3 + B4)            | Delegates to `send_money_policy` — same translation applies.               |
| `update_scheduled_transaction`   | partial (B5 + B6)            | Same. `id` and `recurring` args not checked (CaMeL does not check them).   |
| `update_password`                | done (B7)                    | Direct translation of `is_trusted(password)`.                              |
| `update_user_info`               | done (B8)                    | Direct translation of `all(is_trusted(v) for v in kwargs.values())`.       |

## Per-policy detail

### `send_money`, `schedule_transaction`, `update_scheduled_transaction`

CaMeL ([banking.py:53-98](../../src/camel/pipeline_elements/security_policies/banking.py#L53-L98)):

```
if not is_trusted(recipient): deny
if not can_readers_read_value({recipient.raw}, subject): deny
if not can_readers_read_value({recipient.raw}, amount): deny
if not can_readers_read_value({recipient.raw}, date): deny
allow
```

`schedule_transaction` and `update_scheduled_transaction` both delegate
to this logic. For `update_scheduled_transaction`, the `id` and
`recurring` args are explicitly excluded — CaMeL's comment notes that
`id` does not reach the recipient.

**CTL translation:**

**Gap — reader-set check:** CaMeL's `can_readers_read_value` asks
"is the recipient in the allowed-reader set of this value?" CTL has no
reader sets. The CTL approximation is
**stricter**: it rejects any tainted amount/subject/date even if CaMeL
would allow it because the recipient happens to be in the reader set. (Not sure if being super strict here but ok.)

### `update_password`

CaMeL ([banking.py:100-108](../../src/camel/pipeline_elements/security_policies/banking.py#L100-L108)):

```
if is_trusted(password): allow
else: deny
```

CTL B7: `AG(call_update_password -> password_trusted)`

### `update_user_info`

CaMeL ([banking.py:110-123](../../src/camel/pipeline_elements/security_policies/banking.py#L110-L123)):

```
if all(is_trusted(v) for v in kwargs.values()): allow
else: deny
```

Fields checked: `first_name`, `last_name`, `street`, `city`.

CTL B8: `AG(call_update_user_info -> (first_name_trusted & last_name_trusted & street_trusted & city_trusted))` - FP.


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
<td><code>send_money</code></td>
<td>partial<br>Reader-set checks on amount/subject/date approximated via <code>!_tainted</code> — stricter than CaMeL.</td>
<td><pre><code>recipient = kwargs["recipient"]
if not is_trusted(recipient):
    return Denied(...)
if not can_readers_read_value({recipient.raw}, kwargs["subject"]):
    return Denied(...)
if not can_readers_read_value({recipient.raw}, kwargs["amount"]):
    return Denied(...)
if not can_readers_read_value({recipient.raw}, kwargs["date"]):
    return Denied(...)
return Allowed()</code></pre></td>
<td><pre><code>name="trusted_send_money_recipient",
formula="AG(call_send_money -> recipient_trusted)",

name="untainted_send_money_fields",
formula=(
    "AG(call_send_money -> "
    "(!amount_tainted & !subject_tainted & !date_tainted))"
),
</code></pre></td>
</tr>
<tr>
<td><code>schedule_transaction</code></td>
<td>partial<br>Delegates entirely to <code>send_money_policy</code>; same gap applies.</td>
<td><pre><code>return self.send_money_policy(tool_name, kwargs)</code></pre></td>
<td><pre><code>name="trusted_schedule_transaction_recipient",
formula="AG(call_schedule_transaction -> recipient_trusted)",

name="untainted_schedule_transaction_fields",
formula=(
    "AG(call_schedule_transaction -> "
    "(!amount_tainted & !subject_tainted & !date_tainted))"
),
</code></pre></td>
</tr>
<tr>
<td><code>update_scheduled_transaction</code></td>
<td>partial<br>Delegates to <code>send_money_policy</code>. The <code>id</code> and <code>recurring</code> args are not checked (CaMeL comment: <code>id</code> does not reach the recipient).</td>
<td><pre><code>return self.send_money_policy(tool_name, kwargs)
# id and recurring args intentionally excluded</code></pre></td>
<td><pre><code>name="trusted_update_scheduled_transaction_recipient",
formula=(
    "AG(call_update_scheduled_transaction -> recipient_trusted)"
),

name="untainted_update_scheduled_transaction_fields",
formula=(
    "AG(call_update_scheduled_transaction -> "
    "(!amount_tainted & !subject_tainted & !date_tainted))"
),
</code></pre></td>
</tr>
<tr>
<td><code>update_password</code></td>
<td>1/1</td>
<td><pre><code>if is_trusted(kwargs["password"]):
    return Allowed()
return Denied("The password does not come from the user.")</code></pre></td>
<td><pre><code>name="trusted_password",
formula="AG(call_update_password -> password_trusted)",
</code></pre></td>
</tr>
<tr>
<td><code>update_user_info</code></td>
<td>1/1</td>
<td><pre><code>if all(is_trusted(kwarg) for kwarg in kwargs.values()):
    return Allowed()
return Denied("The user information does not come from the user.")</code></pre></td>
<td><code>name="trusted_user_info_fields",
        formula="AG(call_update_user_info -> (first_name_trusted & last_name_trusted & street_trusted & city_trusted))",
        description=(
            "All fields passed to update_user_info must come from trusted "
            "sources. Prevents attackers from injecting personal info updates "
            "via file content or transaction subjects."
        )</code></td>
</tr>
</tbody>
</table>

## Read-only tool taint comparison

CTL taints unconditionally based on tool name: any tool listed in `READ_ONLY_TOOLS` ([`src/camel/ext/ctl_policies/banking.py:66-73`](../../src/camel/ext/ctl_policies/banking.py#L66-L73)) produces `untrusted`

CaMeL assigns fine-grained `Capabilities(sources, readers)` per return value in [`src/camel/pipeline_elements/agentdojo_function.py:_get_metadata_for_ad`](../../src/camel/pipeline_elements/agentdojo_function.py#L120-L203);

| Tool | CTL taint | CaMeL taint | Security Overlap | Confidentiality Overlap |
|---|---|---|---|---|
| `get_iban` | Trusted ([`banking.py:84`](../../src/camel/ext/ctl_policies/banking.py#L67)) | Trusted, public — `{TrustedToolSource}`, `readers.Public()` ([`agentdojo_function.py:131-138`](../../src/camel/pipeline_elements/agentdojo_function.py#L131-L138)). Non-injectable confirmation data. | full — both trusted | full — CaMeL = `Public`; CTL aligns |
| `get_balance` | Trusted ([`banking.py:85`](../../src/camel/ext/ctl_policies/banking.py#L68)) | Trusted, private — `{TrustedToolSource}`, `readers = frozenset()` ([`agentdojo_function.py:176-182`](../../src/camel/pipeline_elements/agentdojo_function.py#L176-L182)). A float can't carry prompt injection; balance is private. | full — both trusted | none — CaMeL = private (`frozenset()`); CTL has no reader model |
| `get_most_recent_transactions` | Always tainted ([`banking.py:69`](../../src/camel/ext/ctl_policies/banking.py#L69)) | Per-transaction via `_get_transaction_metadata` ([`agentdojo_function.py:74-79`](../../src/camel/pipeline_elements/agentdojo_function.py#L74-L79)): source = `User` if `sender == "me"` else the actual sender (attacker-side transactions → untrusted); readers = `{sender, recipient}`. Outer list wrapped `{TrustedToolSource}` + `Public` ([`agentdojo_function.py:126-130`](../../src/camel/pipeline_elements/agentdojo_function.py#L126-L130)), inner elements keep per-transaction caps. | partial — CTL always taints; CaMeL trusts own outgoing transactions (`sender == "me"`) but taints incoming ones | none — CaMeL readers = `{sender, recipient}` (restricted); CTL has no reader model |
| `get_scheduled_transactions` | Always tainted ([`banking.py:70`](../../src/camel/ext/ctl_policies/banking.py#L70)) | Same as `get_most_recent_transactions` — each `Transaction` tagged via `_get_transaction_metadata` ([`agentdojo_function.py:74-79`](../../src/camel/pipeline_elements/agentdojo_function.py#L74-L79), dispatched at [`agentdojo_function.py:198-199`](../../src/camel/pipeline_elements/agentdojo_function.py#L198-L199)). | partial — same as `get_most_recent_transactions` | none — CaMeL readers = `{sender, recipient}` (restricted); CTL has no reader model |
| `get_user_info` | Trusted ([`banking.py:86`](../../src/camel/ext/ctl_policies/banking.py#L71)) | Source = `User`, readers = `frozenset()` ([`agentdojo_function.py:151-155`](../../src/camel/pipeline_elements/agentdojo_function.py#L151-L155)). User-originated → `is_trusted` returns True, which is why CaMeL allows `update_user_info` to legitimately re-submit these fields. | full — both trusted | none — CaMeL = private (`frozenset()`); CTL has no reader model |


