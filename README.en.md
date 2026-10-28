# Practice 2. Detection rules and how to measure their quality

[Русская версия](README.md)

We find attack indicators in the normalized logs of practice 1 and write them as **Sigma** rules, convert them to Kibana
with one command and get a score for every rule: **precision** (how many false alarms) and **recall** (what part of the attack was caught).
Then we tune the noisy rule. No programming is needed — the rules are filled in from templates.

We work on the practice 1 stand: Elasticsearch and Kibana are already running, the logs are normalized.

## 0. Download the practice

The `P2-detection-rules` folder must sit next to `P1-normalization`:

```bash
cd ~
git clone https://github.com/ObeWan99/P2-detection-rules.git
cd P2-detection-rules
docker compose build
```
`docker compose build` builds the practice tools: the Sigma converter and the rule scoring (1–2 minutes on the first run).

Check that the P1 logs are in place (`source .env` has been run in the `P1-normalization` folder):
```bash
curl -u "elastic:$ELASTIC_PASSWORD" "localhost:9200/_cat/indices/norm-*?v&h=index,docs.count&s=index"
```
✔ `norm-auth` 20000, `norm-system` 15000, `norm-web` 15000

## Workflow

1. Walk through the sample `rules/00-example-web-attack.yml` — **[sigma-reference.en.md](sigma-reference.en.md)**
2. Fill in the templates `rules/01`–`05`: replace `___` with values from Discover
3. Convert the rules to Kibana:
   ```bash
   docker compose run --rm p2 rules
   ```
4. Score the rules:
   ```bash
   docker compose run --rm p2 score
   ```
5. Tune the noisy rule: add an exception, then `rules` and `score` again

## Files

| File | Contents |
|---|---|
| `sigma-reference.md`, `sigma-reference.en.md` | reference: the Sigma format, where to find values, precision and recall |
| `rules/` | sample `00` and rule templates `01`–`05` |
| `docker-compose.yml` | practice tools; they connect to the P1 stand |
| `tools/` | Sigma converter, rule scoring and the training data labels `ground_truth.csv` |

The rule templates and the tool output are in Russian.
