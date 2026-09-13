# secscan

Локальный сканер уязвимостей с веб-интерфейсом (по мотивам hostedscan.com — но
локально, без регистрации и оплат). Вводите IP-адрес или URL — на выходе отчёт
с уязвимостями, отсортированными от самых критичных к менее критичным, и с
описанием, как исправить.

## Сканеры

| Движок      | Что даёт |
|-------------|----------|
| nmap (TCP)  | открытые TCP-порты, сервисы и версии; NSE vulners (CVE+CVSS) и доп. NSE-скрипты (ssl-enum-ciphers — слабые TLS-протоколы/шифры, CRIME; http-methods, http-trace) |
| nmap (UDP)  | топ-50 UDP-портов (медленнее TCP) |
| OWASP ZAP   | анализ веб-приложений (zap-baseline, пассивные правила, русские описания) |
| TLS/SSL     | testssl.sh: протоколы, параметры сервера, security-заголовки https-сайтов |
| nuclei      | тысячи сигнатур-шаблонов (лёгкая замена OpenVAS/Greenbone) |

Все виды проверок выполняются при каждом скане. В главной странице панель
«Ход сканирования» показывает статус каждого этапа выбранной задачи: серый —
ждёт, жёлтый — выполняется, зелёный ✓ — готово, красный ✕ — ошибка этапа,
серый «–» — движка нет в образе (режим «всё в одном», см. ниже).

Ввод цели: `192.168.7.7`, `example.com` или `https://example.com`.
Если это URL — nmap сканирует хост, а ZAP/nuclei дополнительно проверяют
веб-приложение. Для «голого» IP (или домена без схемы) secscan дополнительно
находит другие сайты на этом же IP — по TLS-сертификатам (SAN) и через
публичный реестр сертификатов crt.sh с резервом на certspotter API (оба
отключаются `SECSCAN_CRTSH=0`) — и за
один запуск проверяет каждый: IP по nmap, все найденные домены по http/https
через ZAP/nuclei и testssl (например, ввели IP, а проверятся и
`https://vault.fdkh.ru`, и `https://music.fdkh.ru`, и остальные, чьи A-записи
ведут на этот IP).

Виды проверок включать не нужно — при каждом скане выполняются все (nmap
TCP+UDP с NSE-скриптами, ZAP, TLS/SSL, nuclei); отключить поиск соседних
сайтов на IP можно env `SECSCAN_CRTSH=0`.

## Архитектура

- Один Go-сервис (веб + очередь задач + агрегация отчётов), файловое хранилище
  задач в `data/jobs/*.json` (без СУБД).
- Два режима запуска движков (`SECSCAN_ENGINE_MODE`, см. `engines.go`):
  * `docker` (по умолчанию) — каждый сканер выполняется разовым
    docker-контейнером через docker.sock хоста (`--network host` на Linux);
    образы подтягиваются при первом использовании. Требует Linux-хост со
    смонтированным `docker.sock` (для сканирования LAN как с самого хоста);
  * `local` — сканеры запускаются обычными процессами внутри этого же
    контейнера. Так собирается образ «всё в одном» (`Dockerfile.allinone`:
    nmap + ZAP + nuclei + testssl.sh в одном образе) — он работает и на
    Docker Desktop (macOS/Windows), где `docker.sock` из контейнера
    недоступен, а `--network host` не действует. Отсутствующий движок даёт
    не ошибку, а статус этапа «пропущен» (–).
  Шаблоны nuclei кэшируются в `data/nuclei-templates`.
- Находки всех сканеров приводятся к единой модели (severity:
  critical/high/medium/low/info, CVE, CVSS, описание, рекомендация «как
  исправить», доказательства). Отчёт сортируется по критичности.
- Авторизация: один пользователь (SECSCAN_USER/SECSCAN_PASS), сессия в cookie.

## Запуск: всё в одном контейнере (macOS/Windows, Docker Desktop)

    cd <каталог проекта>
    cp .env.example .env        # задайте SECSCAN_PASS
    docker compose -f docker-compose.allinone.yml up -d --build
    # http://localhost:8510

Всё сканирование идёт внутри ОДНОГО контейнера: `nmap`, `nmap -sU`,
`zap-baseline.py`, `testssl.sh` и `nuclei` лежат в самом образе и запускаются
как локальные процессы (`SECSCAN_ENGINE_MODE=local`). Ни `docker.sock`, ни
`--network host`, ни `SECSCAN_HOST_DATA` не нужны — поэтому этот вариант
работает на macOS (Docker Desktop), где разовые контейнеры-сканеры через
docker.sock не поднимаются.

Образ собирается из `Dockerfile.allinone`: база — официальный
`ghcr.io/zaproxy/zaproxy:stable` (Debian + Java + ZAP), в неё добавляются nmap,
nuclei v2.9.14 и testssl.sh 3.2.4. Архитектура выбирается автоматически
(`TARGETARCH`), так что сборка работает и на Apple Silicon (arm64), и на x86.

Оговорки для Docker Desktop/macOS:
- сканирование LAN-адресов идёт через NAT Docker Desktop: TCP-порты и веб-сайты
  видны нормально, UDP-скан (`-sU`) и определение ОС (`-O`) через NAT
  ненадёжны — этап UDP может дать пустой результат;
- сама машина с Docker снаружи контейнера не «localhost» — цель задавайте
  IP-адресом машины в LAN (например `192.168.7.2`), а не `127.0.0.1`.

## Запуск на Linux-сервере (разовые контейнеры-сканеры)

    cd /opt/projects/secscan
    cp .env.example .env        # задайте SECSCAN_PASS
    docker compose up -d --build
    # http://<server>:8510

Контейнеру нужен доступ к `/var/run/docker.sock` (запуск сканеров) и bind
`./data` на хосте — рабочие каталоги сканеров монтируются по
`SECSCAN_HOST_DATA` (по умолчанию `/opt/projects/secscan/data`; путь внутри
контейнера дублирует хостовый — см. docker-compose.yml).

Образы по умолчанию: `instrumentisto/nmap:latest`,
`ghcr.io/zaproxy/zaproxy:stable`, `projectdiscovery/nuclei:v2.9.14`
(v3 падает SIGILL на старых CPU), `drwetter/testssl.sh:latest`
(переопределяются env `SECSCAN_*_IMAGE`; в режиме «всё в одном» не
используются — движки уже внутри образа). На Windows Docker Desktop задайте
`SECSCAN_DOCKER_NETWORK=` (пусто) — `--network host` там не поддерживается,
либо переходите на вариант «всё в одном».

## Разработка (без docker)

    export SECSCAN_USER=admin SECSCAN_PASS=secret
    go build -o secscan . && ./secscan

Тесты: `go test ./...` (GMP/OpenVAS-код удалён — вместо него nuclei).

## API

    POST /api/scans        {"target":"https://example.com"}  → {"id":"..."}
    GET  /api/scans        список задач (статусы этапов — в поле stages)
    GET  /api/scans/{id}   задача (статус, находки)
    DELETE /api/scans      {"ids":["..."]} — удалить завершённые задачи (в UI: чекбоксы + «Удалить выбранные»)
    GET  /reports/{id}     HTML-отчёт
    GET  /reports/{id}/export.csv|.pdf — экспорт

Все запросы (кроме /login и /healthz) требуют cookie сессии.

## Структура

    main.go          — конфиг, HTTP-сервер, маршруты
    auth.go          — сессии (логин/пароль из env)
    store.go         — файловое хранилище задач
    engine.go        — очередь и исполнение скана (nmap → udp → zap → ssl → nuclei)
    engines.go       — режимы запуска движков: docker (разовые контейнеры) / local
    scanners.go      — обёртка docker run, nmap TCP/UDP (XML), доп. NSE-скрипты
    discovery.go     — поиск сайтов на IP цели (TLS SAN + crt.sh/certspotter), списки целей
    ssl.go           — TLS/SSL-анализ (testssl.sh, JSON)
    nuclei.go        — сигнатурный скан (nuclei, JSONL)
    zap_i18n.go      — русские переводы правил OWASP ZAP
    remediation.go   — база рекомендаций «как исправить»
    models.go        — модель находки/задачи, сортировка по критичности
    report.go        — рендер HTML-отчёта
    web/             — шаблоны (login, index, report)
    docker-compose.yml            — Linux-сервер: сканеры разовыми контейнерами
    Dockerfile.allinone + docker-compose.allinone.yml — «всё в одном» (macOS/Windows)
