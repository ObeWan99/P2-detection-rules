# Practice 2 reference. Sigma rules and how to measure their quality

[Русская версия](sigma-reference.md)

## 1. The Sigma format

**Sigma** is an open format for describing detection rules that does not depend on a particular SIEM. A rule is written once
in a YAML text file and then automatically converted to the query language of the target system (Elastic, Splunk, KUMA, etc.).

YAML rules: each line is a "key: value" pair; nesting is set by indenting with spaces (the Tab character is not allowed).

## 2. Rule structure

```yaml
title: Vulnerability scanner in User-Agent
logsource:
  category: webserver
detection:
  selection:
    event.dataset: web
    user_agent.original|contains:
      - sqlmap
      - nikto
  condition: selection
level: medium
```

| Field | Purpose |
|---|---|
| `title` | Rule name; shown to the on-duty analyst when the rule fires |
| `logsource` | Category of logs the rule applies to |
| `detection` | Detection conditions (section 3) |
| `level` | Severity: `low`, `medium`, `high`, `critical` |

Full rules also contain an identifier (`id`), author, description, a mapping to MITRE ATT&CK (`tags`) and a list
of possible false positives (`falsepositives`). The practice uses a minimal set of fields.

In the practice files the `title` values are in Russian; the rule structure is the same.

## 3. The `detection` section

| Notation | Meaning |
|---|---|
| Several fields in one condition | Logical **AND**: all must match |
| A list of values (lines starting with `-`) | Logical **OR**: one is enough |
| `field: value` | Field equals value |
| `field\|contains: text` | Field contains text |
| `field\|cidr: '10.0.0.0/8'` | IP address belongs to a range (here — all `10.x.x.x` addresses) |
| `field\|exists: true` | Field is present in the event |
| `selection`, `filter` | Named conditions: what we look for and what we exclude |
| `condition: selection and not filter` | Fires when `selection` matches, except for `filter` cases |

Field names come from the ECS schema used in practice 1: `event.action`, `source.ip`, `url.original`, `user_agent.original`,
`process.name`, `process.command_line`, etc.

### Where to find values for a rule

Discover → the data view with all normalized logs (`norm-*`) → period — the week of data, 10–16 March 2025 (as in P1). First **narrow the events with a query**, then
click the field on the left and look at its top values:

| Template | Query in the search bar | Field |
|---|---|---|
| `01` | `event.dataset : "web"` | `user_agent.original` — values that do not look like a browser |
| `02` | `event.dataset : "system"` | `event.action` — SSH connection |
| `03` | `process.name : *` | `process.name` |
| `04` | `process.command_line : *` | `event.action`, then `process.command_line` |
| `05` | `event.dataset : "auth"` | `event.action` — successful login |

Without a query the top is counted over all three logs at once (about 50 thousand events, 21 different `event.action` values); Kibana shows
only the 10 most frequent values and gathers the rare ones into the **Other** row. A query keeps only the needed log or only the events
where the field is filled in — and the value you need gets into the top.

## 4. Measuring rule quality

### 4.1. The confusion matrix

Every log event is either part of an attack or normal activity; for every event the rule either fires
or not. This gives four possible outcomes:

| | Rule fired | Rule did not fire |
|---|---|---|
| **Event is an attack** | **TP** (true positive) — correct alert | **FN** (false negative) — missed attack |
| **Event is normal** | **FP** (false positive) — false alarm | **TN** (true negative) — correctly silent |

The same four outcomes describe any diagnostic test. For example, a test for an infection: sick and the test is positive — TP;
healthy but the test is positive — FP; sick but the test is negative — FN; healthy and the test is negative — TN.
A false positive (FP) is also called a type I error, a miss (FN) — a type II error.

### 4.2. Precision

**Precision = TP / (TP + FP)**

The share of correct alerts among all alerts of the rule. Shows how far the alert can be trusted.

*Example.* The rule "successful login from an external address" fired 784 times; 397 of them are attack events, 387 are logins of remote
employees. Precision = 397 / 784 = 0.51, i.e. 51 %: every second alert is false.

### 4.3. Recall

**Recall = TP / (TP + FN)**

The share of detected attack events among all attack events. Shows what part of the attack was noticed.

*Example.* At the "password guessing and login" stage the attack consists of 1,582 events; the rules detected 397 (successful logins).
Recall = 397 / 1,582 = 0.25, i.e. 25 %: the failed login attempts are not detected by the rules.

### 4.4. Why accuracy is not used

Accuracy = (TP + TN) / (TP + TN + FP + FN). This measure is unsuitable for detection rules:
there are far more normal events than attack events, and a large TN makes any rule look good.

*Example.* The training data has 50,000 events, 3,093 of them are the attack. A rule that never fires has
TN = 46,907 and accuracy 46,907 / 50,000 = 93.8 % — with 0 % recall.

That is why detection rules are scored by precision and recall; TN is not part of either.

### 4.5. The precision–recall trade-off

Widening a rule (new values in the list, fewer exceptions) raises recall but usually lowers precision.
Narrowing a rule (`filter` exceptions, stricter conditions) raises precision but may lower recall.
Every exception creates an area where the rule will not fire on a real attack either.

## 5. Working on the stand

In the `P2-detection-rules` folder, with the P1 stand running:

```bash
docker compose run --rm p2 rules     # convert the rules from the rules/ folder and create them in Kibana
docker compose run --rm p2 score     # compute the precision of each rule and the recall per attack stage
```

The scoring uses the training data labels (`tools/ground_truth.csv`) — a list of all attack events.
In real operation there are no labels: precision is estimated from how on-duty analysts triage the alerts,
recall — during exercises, when an attack is carried out on purpose.
