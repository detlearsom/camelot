# CaMeL policy bugs found during Phase 1 translation

All bugs are in the original CaMeL security policy files under
`src/camel/pipeline_elements/security_policies/`.

---

## Bug 1: Travel: `reserve_car_rental` and `reserve_restaurant` policies are swapped

**File:** [`src/camel/pipeline_elements/security_policies/travel.py:72-79`](../../src/camel/pipeline_elements/security_policies/travel.py#L72-L79)

**Code:**
```python
(
    "reserve_car_rental",
    make_trusted_fields_policy(("restaurant", "start_time")),
),
(
    "reserve_restaurant",
    make_trusted_fields_policy(("company", "start_time", "end_time")),
),
```

**Actual AgentDojo function signatures:**
- `reserve_car_rental(company, start_time, end_time)` — no `restaurant` argument
- `reserve_restaurant(restaurant, start_time)` — no `company` or `end_time` argument

---

## Bug 2: Workspace: `delete_email` policy has weird logic

**File:** [`src/camel/pipeline_elements/security_policies/workspace.py:122-132`](../../src/camel/pipeline_elements/security_policies/workspace.py#L122-L132)

**Code:**
```python
def delete_email_policy(self, ...):
    # Rationale: The email_id should come from an email that was
    # requested by the user directly
    email_id = kwargs["email_id"]
    if is_trusted(email_id):
        return Denied("Email to be deleted does not come directly from user")
    return Allowed()
```

---

## Bug 3: Workspace: `add_calendar_event_participants` checks wrong argument

**File:** [`src/camel/pipeline_elements/security_policies/workspace.py:204-217`](../../src/camel/pipeline_elements/security_policies/workspace.py#L204-L217)

**Code:**
```python
def add_calendar_event_participants_policy(self, ...):
    # Rationale: Participants should be specified by the user, or event
    # data must be public.
    event_id = kwargs["event_id"]
    if not is_trusted(event_id):
        return Denied("Event to be deleted does not come directly from user")
    return Allowed()
```
---

## Bug 4: Travel: `create_calendar_event` raises `NotImplementedError` for untrusted participants

**File:** [`src/camel/pipeline_elements/security_policies/travel.py:125-139`](../../src/camel/pipeline_elements/security_policies/travel.py#L125-L139)

**Code:**
```python
def create_calendar_event_policy(self, ...):
    participants = kwargs["participants"]
    if is_trusted(participants):
        return Allowed()
    raise NotImplementedError()
``