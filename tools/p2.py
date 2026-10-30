#!/usr/bin/env python3
"""
Инструменты практики 2. Запускаются в контейнере рядом со стендом практики 1.

  p2.py rules   — перевести правила Sigma из /rules и создать их в Kibana
  p2.py score   — точность каждого правила и полнота по этапам атаки
"""

import base64
import csv
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
RULES = Path("/rules")
ES = "http://127.0.0.1:9200"
KB = "http://127.0.0.1:5601"
AUTH = "Basic " + base64.b64encode(f"elastic:{os.environ['ELASTIC_PASSWORD']}".encode()).decode()

# Стенд локальный: системный прокси (если есть) не используем
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def call(method, url, body=None):
    data = None
    headers = {"Authorization": AUTH, "kbn-xsrf": "true"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with OPENER.open(req, timeout=300) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {url} -> {e.code}: {e.read().decode()[:500]}")
    except urllib.error.URLError as e:
        raise SystemExit(f"Нет связи со стендом П1 ({url}): {e.reason}. Стенд запущен? docker compose ps в папке P1-normalization")


es = lambda m, p, b=None: call(m, ES + p, b)
kb = lambda m, p, b=None: call(m, KB + p, b)


# ---------------------------------------------------------------- перевод правил

def convert(path):
    """Sigma-файл -> готовое правило Kibana."""
    r = subprocess.run(["sigma", "convert", "-t", "lucene", "--without-pipeline", "-f", "siem_rule_ndjson", path.name],
                       cwd=path.parent, capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines() if l.startswith("{")]
    if r.returncode or not lines:
        err = (r.stderr or r.stdout).strip().splitlines()
        raise ValueError(err[-1] if err else "не удалось перевести")
    return json.loads(lines[0])


def find_rules():
    return kb("GET", "/api/detection_engine/rules/_find?per_page=1000&filter=alert.attributes.tags:sigma").get("data", [])


def unfilled(f):
    """Остался ли ___ в самом правиле. Комментарии не считаются: в шапке заготовки написано «Замените все ___»."""
    try:
        return "___" in json.dumps(yaml.safe_load(f.read_text(encoding="utf-8")), ensure_ascii=False)
    except yaml.YAMLError:
        return False  # ошибку в YAML покажет перевод правила


def rules():
    old = [r["id"] for r in find_rules()]
    if old:
        kb("POST", "/api/detection_engine/rules/_bulk_action", {"action": "delete", "ids": old})
    print("Правила из папки rules:")
    done = 0
    for f in sorted(RULES.glob("*.yml")):
        if unfilled(f):
            print(f"  -  {f.name}: заготовка не заполнена (есть ___) — пропущено")
            continue
        try:
            rule = convert(f)
        except ValueError as e:
            print(f"  !! {f.name}: ошибка в правиле — {e}")
            continue
        name = rule["name"].replace("SIGMA - ", "")
        # в учебных правилах нет id и description — подставляем имя файла и название
        rule_id = rule.get("rule_id") if rule.get("rule_id") not in (None, "None") else f"p2-{f.stem}"
        desc = rule.get("description") if rule.get("description") not in (None, "", "No description") else name
        kb("POST", "/api/detection_engine/rules", {
            "rule_id": rule_id, "name": name,
            "description": desc, "type": "query", "language": "lucene",
            "query": rule["query"], "index": ["norm-*"], "severity": rule["severity"],
            "risk_score": rule["risk_score"], "threat": rule.get("threat", []),
            "false_positives": rule.get("false_positives", []), "enabled": False,
            "interval": "5m", "from": "now-6m", "tags": ["sigma", f.name]})
        print(f"  ok {f.name}: {rule['query']}")
        done += 1
    print(f"Создано правил в Kibana: {done} (Detection rules, метка sigma)")


# ---------------------------------------------------------------- оценка

STAGES = {  # этапы атаки из разметки -> понятные названия
    "recon": "Разведка (сканеры, служебные адреса)",
    "sqli": "SQL-инъекция",
    "path_traversal": "Обход каталогов",
    "xss": "XSS",
    "credential_access": "Подбор пароля и вход",
    "lateral_movement": "SSH на серверы",
    "reverse_shell": "Сетевые утилиты на серверах",
    "persistence": "Задача cron («маяк»)",
    "unknown": "Файлы, созданные атакующими",
}


def truth():
    """Разметка: какие события журналов — атака и какой этап."""
    gt = {}
    for row in csv.DictReader(open(HERE / "ground_truth.csv", encoding="utf-8")):
        gt[(row["timestamp"].rstrip("Z"), row["source_ip"], row["event_type"])] = row["attack_type"]
    return gt


def hits(query):
    r = es("POST", "/norm-*/_search", {"size": 10000, "query": {"query_string": {"query": query}},
                                       "_source": ["@timestamp", "source.ip", "host.ip", "event.action", "event.dataset"]})
    for h in r["hits"]["hits"]:
        s = h["_source"]
        # в разметке у журнала серверов записан адрес самого сервера (source_ip сырого журнала = host.ip)
        ip = (s.get("host") or {}).get("ip") if s["event"]["dataset"] == "system" else (s.get("source") or {}).get("ip")
        yield (s["@timestamp"][:19], ip, s["event"]["action"])


def score():
    gt = truth()
    rows, caught = [], set()
    for r in sorted(find_rules(), key=lambda r: r["tags"][-1]):
        keys = set(hits(r["query"]))
        tp = {k for k in keys if k in gt}
        caught |= tp
        prec = 100 * len(tp) / len(keys) if keys else 0
        stages = sorted({STAGES.get(gt[k], gt[k]) for k in tp})
        rows.append((r["name"], len(keys), len(tp), len(keys) - len(tp), prec, ", ".join(stages) or "—"))
    if not rows:
        print("Правил с меткой sigma нет. Сначала: docker compose run --rm p2 rules")
        return
    w = max(len(x[0]) for x in rows)
    print(f"\n{'Правило':<{w}}  Сработало  Атака  Ложных  Точность  Что поймало")
    for name, n, tp, fp, prec, st in rows:
        print(f"{name:<{w}}  {n:>9}  {tp:>5}  {fp:>6}  {prec:>7.0f}%  {st}")
    print("\nПокрытие атаки всеми правилами вместе:")
    print(f"{'Этап атаки':<40} Событий  Поймано  Полнота")
    by_stage = {}
    for k, st in gt.items():
        by_stage.setdefault(st, [0, 0])[0] += 1
        by_stage[st][1] += k in caught
    for st, (total, got) in sorted(by_stage.items(), key=lambda x: -x[1][1] / x[1][0]):
        print(f"{STAGES.get(st, st):<40} {total:>7}  {got:>7}  {100 * got / total:>6.0f}%")
    total, got = len(gt), len(caught)
    print(f"{'ВСЕГО':<40} {total:>7}  {got:>7}  {100 * got / total:>6.0f}%")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd not in ("rules", "score"):
        raise SystemExit("Команды: rules — перевести правила и создать в Kibana; score — оценить правила")
    {"rules": rules, "score": score}[cmd]()
