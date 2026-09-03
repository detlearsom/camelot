# Slack — CaMeL to CTL translation

Source files:
- CaMeL: [`src/camel/pipeline_elements/security_policies/slack.py`](../../src/camel/pipeline_elements/security_policies/slack.py)
- CTL:   [`src/camel/ext/ctl_policies/slack.py`](../../src/camel/ext/ctl_policies/slack_overlap.py)

## Status

| CaMeL policy                          | CTL translation         | Notes                                                                                  |
|---------------------------------------|-------------------------|----------------------------------------------------------------------------------------|
| `send_direct_message`                 | partial            | Trusted-recipient clause translated; "recipient ∈ readers(body)" clause not modelled.   |
| `send_channel_message`                | none      | Reader-set computation depends on runtime `env.slack.user_channels`; CaMeL handles it.  |
| `add_user_to_channel`                 | done         |  |
| `invite_user_to_slack`                | done        | |
| `remove_user_from_slack`              | done               |                        |
| `post_webpage`                        | none      | `is_public(url)` is value-level, handled by CaMeL. |
| `get_webpage`                         | none      | `is_public(url)` is value-level, handled by CaMeL.                               |


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
<td><code>send_direct_message</code></td>
<td>partly 1/2<br>modelling if a recipient can read a message requires checking `value.metadata.readers_set`. The message is created runtime.</td>
<td><pre><code>recipient = kwargs["recipient"]
if is_trusted(recipient):
    return Allowed()
readers = {recipient.raw}
if can_readers_read_value(readers, kwargs["body"]):
    return Allowed()
return Denied("The recipient can't read the content of the message.")</code></pre></td>
<td><pre><code>name="send_direct_message_trusted_recipient",
formula="AG(call_send_direct_message -> !recipient_trusted)",
description=("Direct messages must not be sent to a trusted recipient."),
</code></pre></td>
</tr>
<tr>
<td><code>send_channel_message</code></td>
<td>none<br>Checks if the user is a part of the chanel. This is done runtime</td>
<td><pre><code>channel = kwargs["channel"].raw
channel_members = {
    user for user, channels
    in self._env.slack.user_channels.items()
    if channel in channels
}
if can_readers_read_value(channel_members, kwargs["body"]):
    return Allowed()
return Denied("The recipient can't read the content of the message.")</code></pre></td>
<td>—</td>
</tr>
<tr>
<td><code>add_user_to_channel</code></td>
<td>2/2</td>
<td><pre><code>make_trusted_fields_policy(("user", "channel"))</code></pre></td>
<td><pre><code>name="add_user_to_channel_workspace_mutation_policy",
formula=(
    "AG(call_add_user_to_channel -> (user_trusted & !user_tainted & channel_trusted & !channel_tainted))"
),
description=("Only add trusted users to trusted workspaces")</code></pre></td>
</tr>
<tr>
<td><code>invite_user_to_slack</code></td>
<td>2/2</td>
<td><pre><code>make_trusted_fields_policy(("user", "user_email"))</code></pre></td>
<td><pre><code>name="invite_user_to_slack_identity_policy",
formula=(
    "AG(call_invite_user_to_slack -> "
    "(user_trusted & !user_tainted & user_email_trusted & !user_email_tainted))"
),
description=(
    "Slack invites mutate workspace membership. The invited user and "
    "email address must be trusted and untainted."
),</code></pre></td>
</tr>
<tr>
<td><code>remove_user_from_slack</code></td>
<td>1/1</td>
<td><pre><code>make_trusted_fields_policy(("user",))</code></pre></td>
<td><pre><code>name="remove_user_from_slack_identity_policy",
formula=(
    "AG(call_remove_user_from_slack -> "
    "(user_trusted & !user_tainted))"
),
description=(
    "Removing a Slack user mutates workspace membership. The target user "
    "must be trusted and untainted."
),</code></pre></td>
</tr>
<tr>
<td><code>post_webpage</code></td>
<td>None<br>We need to keep track of public content, and public urls.</td>
<td><pre><code>if not is_public(kwargs["url"]):
    return Denied("The url is not public")
if not is_public(kwargs["content"]):
    return Denied("The content is not public")
return Allowed()</code></pre></td>
<td>—</td>
</tr>
<tr>
<td><code>get_webpage</code></td>
<td>None<br>We need to keep track of public urls.</td>
<td><pre><code>if not is_public(kwargs["url"]):
    return Denied("The url is not public")
return Allowed()</code></pre></td>
<td>—</td>
</tr>
</tbody>
</table>

## Read-only tool taint comparison

| Tool | CTL taint | CaMeL taint | Security Overlap | Confidentiality Overlap |
|---|---|---|---|---|
| `get_channels` | Always tainted (built-in) | List of `str`. Outer list: untrusted, `Public` ([`agentdojo_function.py:126-130`](../../src/camel/pipeline_elements/agentdojo_function.py#L126-L130)). Inner channel-name strings match the str branch at [`agentdojo_function.py:139-150`](../../src/camel/pipeline_elements/agentdojo_function.py#L139-L150) → untrusted, private (channel names may contain prompt injections). | full — both untrusted | none — inner strings are private in CaMeL; CTL has no reader model |
| `get_users_in_channel` | Always tainted (built-in) | List of `str`. Same as `get_channels` — untrusted at both levels per [`agentdojo_function.py:139-150`](../../src/camel/pipeline_elements/agentdojo_function.py#L139-L150). | full — both untrusted | none — inner strings are private in CaMeL; CTL has no reader model |
| `read_channel_messages` | Always tainted (built-in) | List of `slack.Message`. Each message dispatched to `_get_message_metadata` ([`agentdojo_function.py:82-85`](../../src/camel/pipeline_elements/agentdojo_function.py#L82-L85), dispatched at [`L200-L201`](../../src/camel/pipeline_elements/agentdojo_function.py#L200-L201)): source = `{sender}` (untrusted unless sender == User), readers = `{recipient}`. | partial — CTL always taints; CaMeL trusts messages sent by the user | none — CaMeL readers = `{recipient}` (restricted); CTL has no reader model |
| `read_inbox` | Always tainted (built-in) | List of `Email`. Each email dispatched to `_get_email_metadata` ([`agentdojo_function.py:61-65`](../../src/camel/pipeline_elements/agentdojo_function.py#L61-L65), dispatched at [`L194-L195`](../../src/camel/pipeline_elements/agentdojo_function.py#L194-L195)): source = transformed sender (`User` if Emma else email address — untrusted), readers = `{sender} ∪ recipients ∪ cc ∪ bcc`. | partial — CTL always taints; CaMeL trusts emails sent by Emma | none — CaMeL readers = `{sender} ∪ recipients ∪ cc ∪ bcc` (restricted); CTL has no reader model |
| `get_webpage` | Always tainted (built-in) | `str` matches [`agentdojo_function.py:139-150`](../../src/camel/pipeline_elements/agentdojo_function.py#L139-L150): untrusted, private (web content may contain prompt injections). | full — both untrusted | none — CaMeL = private; CTL has no reader model |


