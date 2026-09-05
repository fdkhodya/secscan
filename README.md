# secscan

Локальный сканер уязвимостей с веб-интерфейсом (по мотивам hostedscan.com — но
локально, без регистрации и оплат). Вводите IP-адрес или URL — на выходе отчёт
с уязвимостями, отсортированными от самых критичных к менее критичным, и с
описанием, как исправить.

## Сканеры

| Движок   | Статус       | Что даёт |
|----------|--------------|----------|
| nmap     | ✅ работает  | открытые порты, сервисы и версии, NSE-скрипты (vulners: CVE+CVSS) |
| OWASP ZAP| ✅ работает  | активное сканирование веб-приложений (zap-baseline) |
| OpenVAS  | ✅ в составе | Greenbone Community Edition в том же docker-compose (профиль `greenbone`); secscan гоняет скан по GMP через общий unix-сокет gvmd |

Ввод цели: `192.168.7.7`, `example.com` или `https://example.com`.
Если это URL — nmap сканирует хост, а ZAP дополнительно проверяет веб-приложение.
Для «голого» IP ZAP запускается автоматически при обнаружении веб-портов.

Виды проверок (OWASP ZAP, OpenVAS, NSE vulners) включаются переключателями на
главной странице; nmap выполняется всегда. Настройки хранятся в
`data/settings.json`, а в каждой задаче сохраняется снимок включённых проверок
на момент запуска.

## Архитектура

- Один Go-сервис (веб + очередь задач + агрегация отчётов), файловое хранилище
  задач в `data/jobs/*.json` (без СУБД).
- Сканеры nmap и ZAP выполняются как разовые docker-контейнеры через docker.sock
  хоста (`--network host` на Linux).
- Greenbone-стек (gvmd, postgres, openvas, notus, GSA…) — сервисы **этого же**
  docker-compose-файла под профилем `greenbone`. secscan подключается к gvmd по
  протоколу GMP через общий volume `gvmd_socket_vol` (unix-сокет
  `/run/gvmd/gvmd.sock`) — как штатные gsad/gvm-tools. Никаких отдельных машин,
  TCP-портов GMP и «мостов».
- Находки всех сканеров приводятся к единой модели (severity:
  critical/high/medium/low/info, CVE, CVSS, описание, рекомендация «как
  исправить», доказательства). Отчёт сортируется по критичности.
- Авторизация: один пользователь (SECSCAN_USER/SECSCAN_PASS), сессия в cookie.

## Запуск (docker)

    cd /opt/projects/secscan
    cp .env.example .env        # задайте SECSCAN_PASS
    docker compose up -d --build
    # http://<server>:8510

Контейнеру нужен доступ к `/var/run/docker.sock` (запуск сканеров nmap/ZAP) и
bind `./data` на хосте — рабочие каталоги сканеров монтируются по
`SECSCAN_HOST_DATA` (по умолчанию `/opt/projects/secscan/data`).

### Greenbone/OpenVAS (тот же compose, профиль greenbone)

Требования: Linux-хост с ~4–8 ГБ свободной RAM и ~20–60 ГБ диска (фиды
скачиваются при первом старте; сам первичный синк занимает заметное время).
На server/europe стеку не хватает памяти — там запускается только secscan.

    docker compose --profile greenbone up -d --build     # весь стек одной командой
    docker compose logs -f gvmd openvasd                 # следить за первичным синком фидов

Первый старт:

1. Дождитесь готовности gvmd (фиды, миграции БД).
2. Задайте пароль администратора gvmd (по умолчанию admin/admin — небезопасно):
       docker compose exec -u gvmd gvmd gvmd --user=admin --new-password='ВАШ_ПАРОЛЬ'
3. Тот же пароль пропишите в `.env`: `SECSCAN_GMP_PASS=ВАШ_ПАРОЛЬ` и включите
   OpenVAS (`SECSCAN_OPENVAS_ENABLED=1`), затем пересоздайте secscan:
       docker compose up -d --build
4. На веб-морде secscan включите переключатель «OpenVAS (Greenbone)».

Веб-интерфейс GSA (Greenbone Security Assistant) — дополнительно, для ручного
управления: https://127.0.0.1 (сертификат самоподписанный). Чтобы открыть GSA
с других машин, задайте `GC_GSA_PORT=0.0.0.0:8443` (и, при желании,
`GC_GSA_API_PORT=0.0.0.0:9392`).

Остановка: `docker compose --profile greenbone down` (данные — в docker-volumes
`*_data_vol`, сохраняются). Удаление данных: `docker compose --profile greenbone down -v`.

## Разработка (без docker)

    export SECSCAN_USER=admin SECSCAN_PASS=secret
    go build -o secscan . && ./secscan

Образы сканеров по умолчанию: `instrumentisto/nmap:latest`,
`ghcr.io/zaproxy/zaproxy:stable` (переопределяются env `SECSCAN_NMAP_IMAGE`,
`SECSCAN_ZAP_IMAGE`). `SECSCAN_ZAP_ENABLED=0` отключает ZAP (удобно при
разработке, не тянуть образ ~1.5 ГБ).

GMP-клиент (gmp.go) покрыт тестом на mock-сокете (`go test ./...`) — проверены
фрейминг запросов и разбор ответов gvmd; полная проверка движка OpenVAS —
при первом запуске стека greenbone на машине с достаточной RAM.

## API

    POST /api/scans        {"target":"https://example.com"}  → {"id":"..."}
    GET  /api/scans        список задач
    GET  /api/scans/{id}   задача (статус, находки)
    DELETE /api/scans      {"ids":["..."]} — удалить завершённые задачи (в UI: чекбоксы + «Удалить выбранные»)
    GET  /api/settings     / PUT /api/settings — включённые виды проверок
    GET  /reports/{id}     HTML-отчёт
    GET  /reports/{id}/export.csv|.pdf — экспорт

Все запросы (кроме /login и /healthz) требуют cookie сессии.

## Структура

    main.go          — конфиг, HTTP-сервер, маршруты
    auth.go          — сессии (логин/пароль из env)
    store.go         — файловое хранилище задач и настроек
    engine.go        — очередь и исполнение скана (nmap → zap → openvas)
    scanners.go      — docker-обёртка, nmap (XML), ZAP (baseline JSON)
    gmp.go           — GMP-клиент к gvmd (unix-сокет): запуск скана, результаты
    remediation.go   — база рекомендаций «как исправить»
    models.go        — модель находки/задачи, сортировка по критичности
    report.go        — рендер HTML-отчёта
    web/             — шаблоны (login, index, report)
    docker-compose.yml — secscan + Greenbone Community Edition (профиль greenbone)
