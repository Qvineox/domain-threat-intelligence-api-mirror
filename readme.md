# Domain Threat Intelligence API

Магистерская диссертация по кибербезопасности на тему обнаружения вредоносных доменов. Ядро приложения и основное API.
Предоставляет интерфейс для работы веб-приложений, пользователей и автономных агентов.
Управляет агентами сканирования, анализирует собранные данные и многое другое.

Ссылки:

- [Main project on GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-api)
- [Mirror on GitHub](https://github.com/Qvineox/domain-threat-intelligence-api-mirror)
- [Master's thesis paper](https://cloud.qvineox.ru/index.php/s/wLg8bncwQWz9Tff)

Экосистема:

- Хаб
    - Основной проект на [GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-hub)
    - Зеркало на [GitHub](https://github.com/Qvineox/domain-threat-intelligence-hub-mirror)
- Агент
    - Основной проект на [GitLab](https://gitlab.qvineox.ru/masters/domain_threat_intelligence)
    - Зеркало на [GitHub](https://github.com/Qvineox/domain-threat-intelligence-agent-mirror)

## Демонстрация

Приложение из ветки STAGING доступно по [ссылке](https://domain-threat-intel-stage.qvineox.ru/login). _Требуется
авторизация._

## Установка и разработка

Этот проект работает в облаке и использует Docker Compose в качестве основного и единственного поддерживаемого метода
развертывания.
Файлы Docker Compose доступны в директории [docker](scripts%2Fdocker).

Все скрипты для разработки доступны в каталоге [scripts](scripts).
[swagger](scripts%2Fswagger).
Этот проект использует Swagger для взаимодействия с API. Скрипты Swagger также доступны
в директории [swagger](scripts%2Fswagger).

### Сборка и запуск

Для сборки и запуска приложения необходимо выполнить следующие команды. Обратите внимание, что необходимые переменные
окружения должны
находиться в директории `./configs/config.json` или в окружении для запуска приложения. Запускается из корня проекта.

```shell
go build -ldflags="-s -w" -o .\build\bin\build.go ./cmd
.\build\bin\build.go
```

### Окружение

В приложении используются следующие переменные. Эти переменные также отображаются в автоматизированном GitLab CI/CD:

| Переменная            | Необходимость | GitLab CI переменная   | Описание                             | Пример                               |
|-----------------------|---------------|------------------------|--------------------------------------|--------------------------------------|
| db_host               |               | $DB_HOST               | Database host                        | 0.0.0.0, database                    |
| db_port               |               | $DB_PORT               | Database port                        | 5432                                 |
| db_user               |               | $DB_USER               | Database user                        | user                                 |
| db_pass               |               | $DB_PASS               | Database user password               | password123!                         |
| db_name               |               | $DB_NAME               | Database name                        | database_name                        |
| db_timezone           |               | $DB_TZ                 | Database timezone                    | Europe/Moscow                        |
| http_port             |               | $HTTP_PORT             | REST port                            | 80                                   |
| http_host             |               | $HTTP_HOST             | REST host                            | localhost                            |
| http_api_path         | optional      | $HTTP_API_PATH         | REST endpoint path                   | /api/v1                              |
| http_swagger_enabled  |               | $HTTP_SWAGGER_ENABLED  | Defines if Swagger routes will start | false                                |   
| http_swagger_host     | optional      | $HTTP_SWAGGER_HOST     | Defines Swagger API host             | localhost:7090                       |   
| http_swagger_version  | optional      | $HTTP_SWAGGER_VERSION  | Swagger endpoint schema version      | v0.0.1                               |   
| http_security_tls     |               | $HTTP_SECURITY_TLS     | Defines if TLS encryption enabled    | false                                |   
| http_security_origins | optional      | $HTTP_SECURITY_ORIGINS | Allowed origins                      | localhost, qvineox.ru                |   
| http_security_domain  | optional      | $HTTP_SECURITY_DOMAIN  | Main domain for cookie auth          | qvineox.ru                           |   
| -                     |               | $TRAEFIK_HOST          | Reverse proxy host rule              | domain-threat-intel-stage.qvineox.ru |   

Дополнительную информацию о конфигурации можно найти в каталоге [configs](configs).

### Непрерывная интеграция с помощью GitLab

Все файлы, необходимые для запуска автоматизированного GitLab CI, находятся в директории [build](build).

## Структура проекта

У разработчиков языка Go нет строгих правил относительно структуры проекта на Go. Однако с годами сложилась одна
схема: [project-layout](https://github.com/golang-standards/project-layout).
Ниже приведен адаптированный вариант, используемый в данном проекте:

- `/cmd` - Основные исходные файлы.
    - `/app` - Логика запуска приложения.
    - `/core` - Основной код приложения.
        - `/entities` - Доменная модель приложения.
        - `/repos` - Репозитории для работы с хранимыми данными.
        - `/services` - Определяет доменную логику с помощью доменных моделей.
    - `/mail` - Почтовый клиент.
    - `/integrations` - Интеграции с внешними сервисами.
- `/internal` - Частный код, не импортируемый в другие приложения или библиотеки.
- `/pkg` - Публичный код, открытый для других.
- `/test` - Дополнительные внешние тесты и тестовые данные.
- `/configs` - Файлы конфигурации.
- `/docs` - Проектные и пользовательские документы.
- `/examples` - Примеры для нашего приложения и/или публичной библиотеки.
- `/api` - Файлы контрактов API (Swagger, Protocol Buffers, etc.).
    - `/proto` - Файлы, используемые при взаимодействии Protocol Buffers/gRPC.
    - `/rest` - Конечные точки REST API.
- `/web` - Активы, специфичные для веб-приложений (статические файлы и т. д.).
- `/build` - Файлы сборки и непрерывной интеграции (CI).
    - `/bin` - Бинарные файлы и файлы компиляции.
    - `/docker` - Файлы для запуска Docker.
- `/scripts` - Скрипты для анализа, установки и так далее.
    - `/docker` - файлы компоновки Docker для запуска приложения.
    - `/idea` - Скрипты разработки в IDE.
- `/vendor` - Зависимости приложения (например, зависимости модулей Go).

Здесь нет каталога /src, как в некоторых других языках. Это объясняется тем, что /src - слишком общий каталог; поэтому
при таком расположении
отдается предпочтение таким каталогам, как /cmd, /internal или /pkg.

> Источник: Manning, 100 Go Mistakes and How to Avoid Them

## Безопасность и соответствие нормативным требованиям

> TODO: добавить...

## Полезные ссылки

### Сервисы

- [Shields.io](https://shields.io/)

### Руководства

- [HABR - "Запускаем PostgreSQL в Docker: от простого к сложному" - 2021](https://habr.com/ru/articles/578744/)
- [HABR - "Разбираемся с пакетом Context в Golang" - 2019](https://habr.com/ru/companies/nixys/articles/461723/)
- [HABR - "Неочевидные проблемы с UUID ключами в PostgreSQL" - 2023](https://habr.com/ru/articles/747348/)
- [YouTube - "Swagger for Go REST APIs: Quick & Easy Documentation with Gin" - 2023](https://youtu.be/0b_N4y8_9iI?si=hqdJT9NGcBtQJbkK)
- [LogRocket - "Gin binding in Go: A tutorial with examples" - 2021](https://blog.logrocket.com/gin-binding-in-go-a-tutorial-with-examples/)
- [LogRocket - "A guide to JWT authentication in Go" - 2022](https://blog.logrocket.com/jwt-authentication-go/)
- [ZetCode - "Go CSV - read & write CSV" - 2023](https://zetcode.com/golang/csv/)