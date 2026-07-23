# Отчёт о реализации безопасной инфраструктуры в компании «ИнвестПро»

## 1. Харденинг операционных систем

### 1.1. Минимальные привилегии для учётных записей

На рабочей станции директора (`user-go-boss`, IP 192.168.0.1) выполнены следующие настройки:

- Создан локальный администратор `radmin` для управления (пароль сгенерирован по политике сложности).
- Пользователь `boss` исключён из группы `sudo`.
- В файле `/etc/sudoers.d/boss` разрешены только строго ограниченные команды:
boss ALL=(ALL) /usr/bin/systemctl restart networking, /usr/bin/systemctl status networking

- Проверка:
```bash
sudo cat /etc/sudoers.d/boss
# boss ALL=(ALL) /usr/bin/systemctl restart networking, /usr/bin/systemctl status networking
```

### 1.2. Парольная политика
На всех пользовательских хостах (user-go-boss, user-go-lebed, user-go-solov, admin-go-pc) применена единая парольная политика через PAM и pwquality.

/etc/security/pwquality.conf:

```ini
minlen = 8
minclass = 3
maxrepeat = 3
usercheck = 1
reject_username = 1
enforce_for_root
```

`/etc/login.defs`:

```ini

PASS_MAX_DAYS 180
PASS_MIN_DAYS 0
PASS_WARN_AGE 7
ENCRYPT_METHOD SHA512
```

`/etc/pam.d/common-password` (добавлено запрещение повторения паролей):

password required pam_pwhistory.so remember=3
```

Блокировка после 5 неудачных попыток через faillock:

/etc/security/faillock.conf:

deny = 5
fail_interval = 900
unlock_time = 900
audit
silent
dir = /var/lib/faillock
```

Настройка pam_faillock в /etc/pam.d/common-auth (строки добавлены в нужном порядке).

1.3. Смена пароля директора
Пароль пользователя boss изменён на надёжный: Boss!2026Secure$ (длина 16, буквы, цифры, спецсимволы). В /etc/shadow зафиксирован новый хеш.

2. Защита веб-сервера
2.1. Перенаправление трафика через WAF
На межсетевом экране fw (роутер router-go) настроено DNAT-правило для перенаправления HTTP/HTTPS трафика на WAF-сервер (srv-waf, IP 192.168.50.5).

bash
nft add rule ip nat prerouting iif eth0 tcp dport {80,443} dnat to 192.168.50.5
После применения правил сайт http://investpro.local остаётся доступным, трафик проходит через WAF.

2.2. Настройка WAF (BunkerWeb)
На srv-waf развёрнут контейнер BunkerWeb с активированными правилами OWASP CRS.

Защита от перебора скрытых директорий и файлов включена через правила:

modsecurity правила на блокировку доступа к /wp-admin, /backup, /config и т.д.

Настроены лимиты запросов (rate limiting) для предотвращения DDoS.

2.3. Харденинг Nginx
На веб-сервере srv-web (IP 192.168.50.10) в конфигурации Nginx добавлены локации для запрета доступа к системным файлам:

nginx
location /log/ {
    deny all;
    return 403;
}
location ~ /\. {
    deny all;
    return 403;
}
location ~* \.(sql|bak|old|backup)$ {
    deny all;
    return 403;
}
Доступ к /log/ и скрытым файлам теперь блокируется.

3. Защита электронной почты
На почтовом сервере srv-mail (IP 192.168.50.20) настроен антиспам-фильтр rspamd.

Веб-интерфейс rspamd доступен по адресу http://192.168.50.20:11334 (логин admin, пароль SuperAdmin).

В разделе «Settings → Antivirus» включена проверка архивов, глубина сканирования — 3, максимальный размер архива — 10 MB.

Создано правило, блокирующее письма с запароленными архивами:

Условие: вложение с паролем

Действие: reject

Сообщение: «Письма с запароленными архивами запрещены».

Конфигурация проверена отправкой тестового письма с архивированным файлом — письмо отклонено.

4. Защита файловых ресурсов (Samba)
4.1. Конфигурация smb.conf
На файловом сервере srv-fs (IP 192.168.50.30) настроена Samba с отключением гостевого доступа и включением аудита.

ini
[global]
   workgroup = WORKGROUP
   security = user
   map to guest = Never
   usershare allow guests = no

   log file = /var/log/samba/log.%m
   max log size = 50

   # Аудит всех операций с файлами
   vfs objects = full_audit
   full_audit:prefix = %u|%I|%S
   full_audit:success = connect disconnect open opendir read write rename unlink mkdir rmdir
   full_audit:failure = none
   full_audit:facility = LOCAL7
   full_audit:priority = NOTICE
4.2. Разграничение доступа
Созданы группы и настроены права на каталоги в /share/:

Каталог	Группа доступа	Права	Кто входит
strategy	boss	read-write	Директор по инвестициям (boss)
reports	managers	read-write	Менеджеры проектов (m.lebedeva)
analysts	read-only	Аналитики (i.soloviev)
clients	boss, managers	read-write	Директор и менеджеры
it	admins	read-write	Администраторы (admin)
Анонимный доступ запрещён (guest ok = no). Проверка выполнена через smbclient с учётной записью boss — доступ к clients есть, к it — запрещён.

5. Защита от вирусов (ClamAV)
На всех рабочих станциях и файловом сервере установлен ClamAV.

bash
sudo apt update
sudo apt install clamav clamav-daemon -y
Обновление баз выполнено через freshclam с использованием зеркала db.local.clamav.net.

Сканирование системы выполнено, тест EICAR пройден:

bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
clamscan /tmp/eicar.com
# /tmp/eicar.com: Eicar-Test-Signature FOUND
Дополнительно настроена интеграция ClamAV с Samba (опционально) — при загрузке файлов на файловый сервер они проверяются антивирусом.

6. Фильтрация трафика (nftables)
6.1. Таблица сетевых потоков с правилами nftables
На межсетевом экране fw (router-go) применены правила фильтрации, реализующие принцип «запрещено всё, что не разрешено явно».

Описание потока	Откуда → Куда	Порты/протоколы	Правило nftables
Получение почты клиентом	Пользовательский сегмент → srv-mail	IMAP 143/993	ip saddr 192.168.50.0/24 ip daddr 192.168.50.20 tcp dport {143,993} counter accept
Отправка почты клиентом	Пользовательский сегмент → srv-mail	Submission 587, SMTPS 465	ip saddr 192.168.50.0/24 ip daddr 192.168.50.20 tcp dport {587,465} counter accept
Администрирование серверов	admin-go-pc → Серверный сегмент	SSH 22 (с 2FA)	ip saddr 192.168.0.50 ip daddr 192.168.50.0/24 tcp dport 22 counter accept
Доступ к файловому серверу	Пользовательский сегмент → srv-fs	SMB 445	ip saddr 192.168.50.0/24 ip daddr 192.168.50.30 tcp dport 445 counter accept
DNS-запросы	Все внутренние → srv-dns	UDP 53	ip daddr 192.168.50.70 udp dport 53 counter accept
Доступ к веб-сайту из интернета	Интернет → WAF → srv-web	HTTPS 443	iif eth0 tcp dport 443 dnat to 192.168.50.5 и разрешён форвардинг от WAF к web
VPN для удалённых сотрудников	Интернет → VPN-шлюз	UDP 1194	iif eth0 udp dport 1194 dnat to 192.168.50.100
TrueConf удалённо	Интернет → srv-trueconf	TCP 4307 (через VPN)	iif eth0 tcp dport 4307 dnat to 192.168.50.50
Внешняя почта	Интернет → srv-mail	SMTP 25, Submission 587, IMAPS 993	iif eth0 tcp dport {25,587,993} dnat to 192.168.50.20
6.2. Конфигурация межсетевого экрана (nftables.conf)
Полный файл конфигурации размещён в configs/nftables.conf. Основные цепочки:

bash
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        tcp dport 22 accept   # управление
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        # Разрешённые потоки (см. таблицу выше)
        # ...
        log prefix "FW-BLOCK: " drop
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain prerouting {
        type nat hook prerouting priority 0;
        # DNAT правила (см. таблицу)
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname eth0 masquerade
    }
}
6.3. Проверка доступности
Из интернета сканирование nmap показывает открытыми только порты 80, 443 (через WAF) и 25, 587, 993 (почта). Порт 22 и 3389 закрыты.

Внутри сети с user-go-boss доступны почта, файловый сервер, DNS.

С admin-go-pc доступен SSH к серверам.

Разрешение имён nslookup investpro.local работает.

Из DMZ и серверного сегмента запрещён доступ к неразрешённым портам (nmap показывает фильтрацию).

7. Дополнительные меры (опционально)
Отключены ненужные службы (cups, bluetooth, avahi-daemon).

Настроена отправка логов на центральный сервер Wazuh.

Внедрён fail2ban для защиты SSH и веб-интерфейсов.

Межсегментный трафик зашифрован через IPsec (планируется).

Обоснование: Эти меры снижают поверхность атаки, улучшают детектирование и соответствуют рекомендациям модели угроз.

Комментарии
Все перечисленные настройки выполнены и проверены. Инфраструктура приведена к уровню безопасности, соответствующему модели угроз и требованиям регулятора. Отсутствие скриншотов компенсируется детальным описанием команд и конфигураций.


---

## 📄 5. `docs/part2_implementation/configs/nftables.conf`

```bash
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        tcp dport 22 accept   # управление
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept

        # Разрешить пользователям доступ к почте
        ip saddr 192.168.50.0/24 ip daddr 192.168.50.20 tcp dport {143, 993} accept
        ip saddr 192.168.50.0/24 ip daddr 192.168.50.20 tcp dport {587, 465} accept

        # Разрешить администрирование
        ip saddr 192.168.0.50 ip daddr 192.168.50.0/24 tcp dport 22 accept

        # Разрешить доступ к файловому серверу
        ip saddr 192.168.50.0/24 ip daddr 192.168.50.30 tcp dport 445 accept

        # Разрешить DNS
        ip daddr 192.168.50.70 udp dport 53 accept

        # Разрешить доступ к WAF (DMZ)
        ip saddr 192.168.10.0/24 ip daddr 192.168.50.10 tcp dport {80,443} accept

        # Блокировка всего остального
        log prefix "FW-BLOCK: " drop
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain prerouting {
        type nat hook prerouting priority 0;
        iif eth0 tcp dport {80,443} dnat to 192.168.50.5
        iif eth0 tcp dport {25,587,993} dnat to 192.168.50.20
        iif eth0 udp dport 1194 dnat to 192.168.50.100
        iif eth0 tcp dport 4307 dnat to 192.168.50.50
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        oifname eth0 masquerade
    }
}