package main

import (
	"fmt"
	"strings"
)

// weakService возвращает повышенную критичность/заголовок для заведомо
// небезопасных или устаревших сервисов.
func weakService(service string, port int) (Severity, string, bool) {
	switch service {
	case "telnet":
		return SevHigh, "Открыт telnet — трафик и пароли передаются открыто", true
	case "ftp":
		return SevMedium, "Открыт FTP — учётные данные передаются без шифрования", true
	case "snmp":
		return SevMedium, "Открыт SNMP — проверьте community-строки", true
	case "rdp":
		return SevMedium, "Открыт RDP — ограничьте доступ и включите NLA", true
	case "vnc":
		return SevHigh, "Открыт VNC — проверьте пароль и шифрование", true
	case "x11":
		return SevHigh, "Открыт X11 — разрешён перехват ввода/вывода", true
	case "mysql", "mariadb":
		return SevMedium, "Открыт MySQL/MariaDB — ограничьте доступ к порту", true
	case "postgresql", "postgres":
		return SevMedium, "Открыт PostgreSQL — ограничьте доступ к порту", true
	case "redis":
		return SevHigh, "Открыт Redis — возможен запуск команд без аутентификации", true
	case "mongodb":
		return SevHigh, "Открыт MongoDB — возможен доступ без аутентификации", true
	case "docker":
		return SevHigh, "Открыт Docker API — возможен полный захват хоста", true
	case "kubernetes":
		return SevHigh, "Открыт Kubernetes API", true
	case "smtp":
		return SevLow, "Открыт SMTP — проверьте open-relay", true
	case "pop3", "imap":
		return SevLow, "Открыт POP3/IMAP без TLS — данные передаются открыто", true
	case "http-proxy", "proxy", "socks":
		return SevMedium, "Открыт прокси — возможен open-proxy", true
	default:
		return "", "", false
	}
}

// remediationForService возвращает рекомендацию по закрытию/защите сервиса.
func remediationForService(service string, port int) string {
	switch service {
	case "telnet":
		return "Отключите telnet. Используйте SSH (порт 22) с ключами; отключите вход по паролю."
	case "ftp":
		return "Замените FTP на SFTP/FTPS. Если FTP обязателен — ограничьте доступ по IP и включите TLS."
	case "snmp":
		return "Замените SNMPv1/v2c на SNMPv3 с аутентификацией, смените community-строки, закройте порт 161/udp файрволом."
	case "rdp":
		return "Ограничьте доступ к 3389 файрволом/VPN, включите NLA, используйте надёжные пароли и двухфакторную аутентификацию."
	case "vnc":
		return "Используйте SSH-туннель или VPN для доступа к VNC; включите шифрование (VNC over TLS/SSH)."
	case "x11":
		return "Закройте порт X11 (6000+) файрволом; используйте SSH X11-Forwarding вместо открытого X."
	case "mysql", "mariadb", "postgresql", "postgres":
		return fmt.Sprintf("Ограничьте доступ к порту %d файрволом (только доверенные хосты), используйте сильные пароли и TLS-соединения.", port)
	case "redis":
		return "Redis не должен быть доступен снаружи: закройте порт, включите requirepass и режим protected-mode."
	case "mongodb":
		return "Закройте порт 27017 снаружи, включите авторизацию и bind к localhost/внутренней сети."
	case "docker":
		return "Docker API снаружи — критический риск: закройте порт, используйте TLS-сертификаты или удалённый доступ через VPN."
	case "kubernetes":
		return "Ограничьте доступ к API-серверу (файрвол/VPN), включите RBAC и TLS."
	case "smtp":
		return "Проверьте отсутствие open-relay, включите STARTTLS и ограничьте приём почты."
	case "pop3", "imap":
		return "Требуйте STARTTLS/SSL для почтовых протоколов, ограничьте доступ файрволом."
	case "http-proxy", "proxy", "socks":
		return "Прокси в открытом доступе — закройте порт или ограничьте клиентов; включите аутентификацию."
	default:
		return fmt.Sprintf("Проверьте необходимость открытого порта %d и ограничьте доступ файрволом; держите %s актуальным.", port, service)
	}
}

// genericWebRemediation — универсальная рекомендация для веб-находок без solution.
func genericWebRemediation() string {
	return "Обновите веб-приложение и компоненты до актуальных версий, закройте лишние функции, используйте безопасные заголовки и HTTPS."
}

var _ = strings.TrimSpace
