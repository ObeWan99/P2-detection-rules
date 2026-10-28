# Практика 2. Правила обнаружения и оценка их качества

[English version](README.en.md)

Признаки атаки находим в нормализованных журналах практики 1 и записываем как правила **Sigma**, переводим их в Kibana одной командой
и получаем оценку каждого правила: **точность** (сколько ложных тревог) и **полноту** (какую часть атаки поймали).
Затем настраиваем шумное правило. Программировать не нужно — правила заполняются по заготовкам.

Работаем на стенде практики 1: Elasticsearch и Kibana уже запущены, журналы нормализованы.

## 0. Скачать практику

Папка `P2-detection-rules` должна лежать рядом с `P1-normalization`:

```bash
cd ~
git clone https://github.com/ObeWan99/P2-detection-rules.git
cd P2-detection-rules
docker compose build
```
`docker compose build` собирает инструменты практики: переводчик Sigma и оценку правил (1–2 минуты при первом запуске).

Проверить, что журналы из П1 на месте (в папке `P1-normalization` выполнен `source .env`):
```bash
curl -u "elastic:$ELASTIC_PASSWORD" "localhost:9200/_cat/indices/norm-*?v&h=index,docs.count&s=index"
```
✔ `norm-auth` 20000, `norm-system` 15000, `norm-web` 15000

## Порядок работы

1. Разобрать образец `rules/00-example-web-attack.yml` — **[sigma-reference.md](sigma-reference.md)**
2. Заполнить заготовки `rules/01`–`05`: вместо `___` вписать значения из Discover
3. Перевести правила в Kibana:
   ```bash
   docker compose run --rm p2 rules
   ```
4. Оценить правила:
   ```bash
   docker compose run --rm p2 score
   ```
5. Настроить шумное правило: добавить исключение, снова `rules` и `score`

## Файлы

| Файл | Содержимое |
|---|---|
| `sigma-reference.md` | справка: формат Sigma, где найти значения, точность и полнота |
| `rules/` | образец `00` и заготовки правил `01`–`05` |
| `docker-compose.yml` | инструменты практики; подключаются к стенду П1 |
| `tools/` | переводчик Sigma, оценка правил и разметка учебных данных `ground_truth.csv` |
