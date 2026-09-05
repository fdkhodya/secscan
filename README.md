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
| OpenVAS  | 🚧 в разработке | сканирование уязвимостей (Greenbone) — подключим отдельным движком |

Ввод цели: `192.168.7.7`, `example.com` или `https://example.com`.
Если это URL — nmap сканирует хост, а ZAP дополнительно проверяет веб-приложение.
Для «голого» IP ZAP запускается автоматически при обнаружении веб-портов.

## Архитектура

- Один Go-сервис (веб + очередь задач + агрегация отчётов), файловое хранилище
  задач в `data/jobs/*.json` (без СУБД).
- Сканеры выполняются как docker-контейнеры (`--network host`) через docker.sock
  хоста: образы nmap и ZAP подтягиваются при первом использовании.
- Находки всех сканеров приводятся к единой модели (severity: critical/high/
  medium/low/info, CVE, CVSS, описание, рекомендация «как исправить»,
  доказательства). Отчёт сортируется по критичности.
- Авторизация: один пользователь (SECSCAN_USER/SECSCAN_PASS), сессия в cookie.

## Запуск (docker)

    cd /opt/projects/secscan
    cp .env.example .env        # задайте SECSCAN_PASS
    docker compose up -d --build
    # http://<server>:8510

Контейнеру нужен доступ к `/var/run/docker.sock` (запуск сканеров) и bind
`./data` на хосте — рабочие каталоги сканеров монтируются по
`SECSCAN_HOST_DATA` (по умолчанию `/opt/projects/secscan/data`).

## Разработка (без docker)

    export SECSCAN_USER=admin SECSCAN_PASS=secret
    go build -o secscan . && ./secscan

Образы сканеров по умолчанию: `instrumentisto/nmap:latest`,
`ghcr.io/zaproxy/zaproxy:stable` (переопределяются env `SECSCAN_NMAP_IMAGE`,
`SECSCAN_ZAP_IMAGE`). `SECSCAN_ZAP_ENABLED=0` отключает ZAP (удобно при
разработке, не тянуть образ ~1.5 ГБ).
`SECSCAN_DOCKER_NETWORK=host` (по умолчанию) — сканеры в сети хоста; на
Docker Desktop задайте пустое значение (`SECSCAN_DOCKER_NETWORK=`) — будет
обычная bridge-сеть (на Windows `--network host` не поддерживается).

## Запуск на Windows (мощная машина для полных сканов)

Скомпилированный бинарник `secscan.exe` (amd64) запускается локально:

    set SECSCAN_USER=admin
    set SECSCAN_PASS=ваш-пароль
    set SECSCAN_DATA=C:\secscan\data
    set SECSCAN_HOST_DATA=C:\secscan\data
    set SECSCAN_DOCKER_NETWORK=
    secscan.exe            # http://127.0.0.1:8510

Требования: установленный Docker Desktop (Linux-контейнеры, запущен) с CLI в
PATH. При первом веб-скане подтянется образ ZAP (~1.5 ГБ). Для сканирования
самого Windows-хоста указывайте его LAN-IP (из bridge-контейнера localhost —
это VM Docker). Greenbone/OpenVAS на этой машине — отдельный шаг (docker
compose + интеграция движка в secscan).

## API

    POST /api/scans        {"target":"https://example.com"}  → {"id":"..."}
    GET  /api/scans        список задач
    GET  /api/scans/{id}   задача (статус, находки)
    GET  /reports/{id}     HTML-отчёт

Все запросы (кроме /login и /healthz) требуют cookie сессии.

## Roadmap

- [ ] OpenVAS (Greenbone) как третий движок (отдельный хост/контейнер)
- [ ] Экспорт отчёта (PDF/CSV), тёмная/светлая тема
- [ ] Расписание сканов (cron), сравнение результатов по времени
- [ ] БД-хранилище вместо JSON-файлов, пагинация
- [ ] Продвинутые опции: диапазоны портов, профили сканов, веб-логин для ZAP

## Структура

    main.go          — конфиг, HTTP-сервер, маршруты
    auth.go          — сессии (логин/пароль из env)
    store.go         — файловое хранилище задач
    engine.go        — очередь и исполнение скана (nmap → zap → openvas)
    scanners.go      — docker-обёртка, nmap (XML), ZAP (baseline JSON), OpenVAS-stub
    remediation.go   — база рекомендаций «как исправить»
    models.go        — модель находки/задачи, сортировка по критичности
    report.go        — рендер HTML-отчёта
    web/             — шаблоны (login, index, report)
