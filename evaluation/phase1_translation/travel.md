# Travel — CaMeL to CTL translation

Source files:
- CaMeL: [`src/camel/pipeline_elements/security_policies/travel.py`](../../src/camel/pipeline_elements/security_policies/travel.py)
- CTL:   [`src/camel/ext/ctl_policies/travel.py`](../../src/camel/ext/ctl_policies/travel.py)
## Status

| CaMeL policy              | CTL translation  | Notes                                                                                |
|---------------------------|------------------|--------------------------------------------------------------------------------------|
| `send_email`              | partial (T1)     | Recipient trusted check translated; reader-set check on body/subject out of scope.  |
| `create_calendar_event`   | done (T2)        | CaMeL's implementation is incomplete (raises `NotImplementedError` for untrusted participants); CTL enforces the intended behaviour. |
| `cancel_calendar_event`   | done (T3)        | Direct translation of `is_trusted(event_id)`.                                       |
| `reserve_hotel`           | done (T4)        | Direct translation of `make_trusted_fields_policy(("hotel", "start_day", "end_day"))`. |
| `reserve_car_rental`      | done (T5)        | CaMeL policy has a field-name bug (see below); CTL uses correct field names.         |
| `reserve_restaurant`      | done (T6)        | CaMeL policy has a field-name bug (see below); CTL uses correct field names.         |

## Per-policy detail

### `send_email`

CaMeL ([travel.py:83-123](../../src/camel/pipeline_elements/security_policies/travel.py#L83-L123)):

CTL T1: `AG(call_send_email -> recipients_trusted)`

Translates the `is_trusted(recipients)` clause for primary recipients.
`cc` and `bcc` are optional args - we do not include them.

### `create_calendar_event`

CaMeL ([travel.py:125-139](../../src/camel/pipeline_elements/security_policies/travel.py#L125-L139)):

```
if is_trusted(participants): allow
else: raise NotImplementedError()
```

CaMeL's implementation raises `NotImplementedError`
for the untrusted case rather than denying. CTL T2 enforces the clearly
intended behaviour: `AG(call_create_calendar_event -> participants_trusted)`.

### `cancel_calendar_event`

CaMeL ([travel.py:141-151](../../src/camel/pipeline_elements/security_policies/travel.py#L141-L151)):

```
if not is_trusted(event_id): deny
allow
```

CTL T3: `AG(call_cancel_calendar_event -> event_id_trusted)` — exact translation. 

### `reserve_hotel`

CaMeL: `make_trusted_fields_policy(("hotel", "start_day", "end_day"))`.
Actual AgentDojo args: `hotel, start_day, end_day`. 

CTL T4: `AG(call_reserve_hotel -> (hotel_trusted & start_day_trusted & end_day_trusted))`

### `reserve_car_rental` 

CaMeL: `make_trusted_fields_policy(("restaurant", "start_time"))`.
Actual AgentDojo args: `company, start_time, end_time`.

CTL T5 uses the field names:
`AG(call_reserve_car_rental -> (company_trusted & start_time_trusted))`.
`end_time` is optional and excluded to avoid false positives.

### `reserve_restaurant`

CaMeL: `make_trusted_fields_policy(("company", "start_time", "end_time"))`.
Actual AgentDojo args: `restaurant, start_time`.

Neither `"company"` nor `"end_time"` exist in `reserve_restaurant`'s
kwargs — both raise `KeyError`. 

CTL T6 uses the correct field names:
`AG(call_reserve_restaurant -> (restaurant_trusted & start_time_trusted))`. ✓

## Summary

**Notable finding:** CaMeL's `reserve_car_rental` and `reserve_restaurant`
policies have swapped field names, causing both to raise `KeyError` at
runtime. This is a pre-existing bug in CaMeL's travel suite that the CTL
translation surfaced.

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
<td>partial <br>Reader-set checks on body, subject, and attachments are runtime-only and not modelled.</td>
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
<td><code>create_calendar_event</code></td>
<td>1/1</td>
<td><pre><code>participants = kwargs["participants"]
if is_trusted(participants):
    return Allowed()
raise NotImplementedError()</code></pre></td>
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
<td><code>reserve_hotel</code></td>
<td>1/1</td>
<td><pre><code>make_trusted_fields_policy(("hotel", "start_day", "end_day"))</code></pre></td>
<td><pre><code>name="trusted_hotel_reservation",
formula=(
    "AG(call_reserve_hotel -> "
    "(hotel_trusted & start_day_trusted & end_day_trusted))"
),
</code></pre></td>
</tr>
<tr>
<td><code>reserve_car_rental</code></td>
<td>1/1<br>CaMeL bug: checks field names <code>"restaurant"</code> and <code>"start_time"</code> — wrong tool; raises <code>KeyError</code> at runtime. CTL uses correct names.</td>
<td><pre><code>make_trusted_fields_policy(("restaurant", "start_time"))
# bug: should be ("company", "start_time")</code></pre></td>
<td><pre><code>name="trusted_car_rental_reservation",
formula=(
    "AG(call_reserve_car_rental -> "
    "(company_trusted & start_time_trusted))"
),
</code></pre></td>
</tr>
<tr>
<td><code>reserve_restaurant</code></td>
<td>1/1<br>CaMeL bug: checks <code>"company"</code>, <code>"start_time"</code>, <code>"end_time"</code> — none of which exist in this tool's kwargs; raises <code>KeyError</code> at runtime. CTL uses correct names.</td>
<td><pre><code>make_trusted_fields_policy(("company", "start_time", "end_time"))
# bug: should be ("restaurant", "start_time")</code></pre></td>
<td><pre><code>name="trusted_restaurant_reservation",
formula=(
    "AG(call_reserve_restaurant -> "
    "(restaurant_trusted & start_time_trusted))"
),
</code></pre></td>
</tr>
</tbody>
</table>

## Read-only tool taint comparison

CTL taints unconditionally based on tool name: any tool in [`READ_ONLY_TOOLS`](../../src/camel/ext/ctl_policies/travel.py#L82-L88) produces `untrusted`; any tool in [`TRUSTED_READ_TOOLS`](../../src/camel/ext/ctl_policies/travel.py#L94-L112) is stamped trusted regardless of inputs. Tainting is applied in [`state_machine.py:131-134`](../../src/camel/ext/state_machine.py#L131-L134).

CaMeL assigns fine-grained `Capabilities(sources, readers)` per return value in [`_get_metadata_for_ad`](../../src/camel/pipeline_elements/agentdojo_function.py#L120-L203). The travel-specific `_TRUSTED_TRAVEL_TOOLS` and `_UNTRUSTED_TRAVEL_TOOLS` sets are at [`agentdojo_function.py:91-117`](../../src/camel/pipeline_elements/agentdojo_function.py#L91-L117).

| Tool(s) | CTL taint | CaMeL taint | Security Overlap | Confidentiality Overlap |
|---|---|---|---|---|
| `get_user_information` | Trusted ([`travel.py:95`](../../src/camel/ext/ctl_policies/travel.py#L95)) | `dict` matches [`agentdojo_function.py:151-155`](../../src/camel/pipeline_elements/agentdojo_function.py#L151-L155): source = `{User}` on the outer dict, readers = `frozenset()` → **trusted**, private. Note CaMeL only stamps the outer container; inner field values keep the default `Tool(...)` source with empty `inner_sources` and are untrusted on extraction (see [workspace.md or analysis notes for this asymmetry](#)). | full — both trusted | none — CaMeL marks readers as private (`frozenset()`); CTL has no reader model |
| `get_all_hotels_in_city`, `get_hotels_prices`, `get_hotels_address`, `get_all_restaurants_in_city`, `get_cuisine_type_for_restaurants`, `get_restaurants_address`, `get_dietary_restrictions_for_all_restaurants`, `get_contact_information_for_restaurants`, `get_price_for_restaurants`, `check_restaurant_opening_hours`, `get_all_car_rental_companies_in_city`, `get_car_types_available`, `get_car_fuel_options`, `get_car_rental_address`, `get_car_price_per_day`, `get_flight_information` | Trusted ([`travel.py:96-111`](../../src/camel/ext/ctl_policies/travel.py#L96-L111)) | All in `_TRUSTED_TRAVEL_TOOLS`. Match [`agentdojo_function.py:161-167`](../../src/camel/pipeline_elements/agentdojo_function.py#L161-L167): source = `{TrustedToolSource}` on the outer container, readers = `Public` → **trusted**, public. CaMeL treats catalog data as injection-free. | full — both trusted, same tool set | full — CaMeL marks readers as `Public`; CTL's absence of reader model aligns |
| `get_rating_reviews_for_hotels`, `get_rating_reviews_for_restaurants`, `get_rating_reviews_for_car_rental` | Always tainted ([`travel.py:83-85`](../../src/camel/ext/ctl_policies/travel.py#L83-L85)) | In `_UNTRUSTED_TRAVEL_TOOLS`. Outer dict match [`agentdojo_function.py:156-160`](../../src/camel/pipeline_elements/agentdojo_function.py#L156-L160): source = `{Tool(...,{User})}`, readers = `Public`. CaMeL labels the outer wrapper `User`-sourced, but inner review strings retain the default untrusted `Tool(...)` source (empty `inner_sources`) from `wrap_output`, so values pulled out of reviews are untrusted in practice — matching CTL's coarse taint. | partial — same practical outcome (untrusted in practice) but different mechanisms: CTL taints the whole output; CaMeL's outer wrapper is misleadingly `{User}`-sourced while inner values remain untrusted | full — CaMeL readers = `Public`; CTL aligns |
| `search_calendar_events`, `get_day_calendar_events` | Always tainted ([`travel.py:86-87`](../../src/camel/ext/ctl_policies/travel.py#L86-L87)) | List of `CalendarEvent`. `_get_calendar_event_metadata` ([`agentdojo_function.py:40-48`](../../src/camel/pipeline_elements/agentdojo_function.py#L40-L48), dispatched at [`L190-L191`](../../src/camel/pipeline_elements/agentdojo_function.py#L190-L191)): per-event source = transformed participants (`User` if Emma, else the participant address — untrusted), readers = `participants`. CTL approximates conservatively because the per-event trust level cannot be expressed as a single static taint. | partial — CTL always taints; CaMeL computes per-event trust from participants (events organised by the user would be trusted in CaMeL but tainted in CTL) | none — CaMeL readers = `participants` (restricted); CTL has no reader model |
