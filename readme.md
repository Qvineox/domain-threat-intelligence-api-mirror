# Domain Threat Intelligence API

Master's thesis in Cybersecurity on malicious domain detection. Central core application.
Provides API for Web application and users. Controls scanning agents, report analysis and more.

This project is mirrored from GitLab.

Links:

- [Main project on GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-api)
- [Mirror on GitHub](https://github.com/Qvineox/domain-threat-intelligence-api-mirror)
- [Master's thesis paper](https://cloud.qvineox.ru/index.php/s/wLg8bncwQWz9Tff)

Ecosystem:

- Hub
    - Main project on [GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-hub)
    - Mirror on [GitHub](https://github.com/Qvineox/domain-threat-intelligence-hub-mirror)
- Agent
    - Main project on [GitLab](https://gitlab.qvineox.ru/masters/domain_threat_intelligence)
    - Mirror on [GitHub](https://github.com/Qvineox/domain-threat-intelligence-agent-mirror)

## Setup and deployment

This project is cloud based and uses Docker Compose as it's primary and only supported method of deployment.
Docker-compose files are available in [docker](scripts%2Fdocker) directory.

All development scripts are available in [scripts](scripts) directory.
[swagger](scripts%2Fswagger)
This project uses Swagger to communicate with the API. Swagger scripts are also available
in [swagger](scripts%2Fswagger) directory.

### Building and running

Following commands should be executed to build and run the application. Note that required environment variables should
be in `./configs/config.json` directory or in environment to start the application. Runs from project root.

```shell
go build -ldflags="-s -w" -o .\build\bin\build.go ./cmd
.\build\bin\build.go
```

### Environment

Following variables are used in application. These variables are also mapped in automated GitLab CI/CD:

| Environment Variable | Is Required? | GitLab CI Variable    | Description                                                           | Example values    |
|----------------------|--------------|-----------------------|-----------------------------------------------------------------------|-------------------|
| db_host              |              | $DB_HOST              | Database host                                                         | 0.0.0.0, database |
| db_port              |              | $DB_PORT              | Database port                                                         | 5432              |
| db_user              |              | $DB_USER              | Database user                                                         | user              |
| db_pass              |              | $DB_PASS              | Database user password                                                | password123!      |
| db_name              |              | $DB_NAME              | Database name                                                         | database_name     |
| db_timezone          |              | $DB_TZ                | Database timezone                                                     | Europe/Moscow     |
| http_port            |              | $WEB_PORT             | REST port                                                             | 80                |
| http_host            |              | $WEB_HOST             | REST host                                                             | localhost         |
| http_base_path       | optional     | $HTTP_BASE_PATH       | REST endpoint path                                                    | /api/v1           |
| http_api_version     | optional     | $HTTP_API_VERSION     | REST endpoint schema version                                          | v0.0.1            |
| http_swagger_enabled | optional     | $HTTP_SWAGGER_ENABLED | Defines if [swagger](scripts%2Fswagger%2Freadme.md) routes will start | false             |   
| http_swagger_host    | optional     | $HTTP_SWAGGER_HOST    | Defines [swagger](scripts%2Fswagger%2Freadme.md) API route            | localhost:7090    |   
| allowed_origin       | optional     | $HTTP_SUBDOMAIN       | Defines if [swagger](scripts%2Fswagger%2Freadme.md) starts            | localhost         |   

### Continuous integration using GitLab

All the files required to run automated GitLab CI are located in [build](build) directory.

## Project structure

The Go language maintainer has no strong convention about structuring a project in Go. However, one layout has emerged
over the years: [project-layout](https://github.com/golang-standards/project-layout).
If our project is small enough (only a few files), or if our organization has already created its standard, it may not
be worth using or migrating to project-layout. Other-wise, it might be worth considering. Let’s look at this layout and
see what the main directories are:

- `/cmd` - The main source files.
    - `/app` - Application startup logic.
    - `/core` - Main application code.
        - `/entities` - Core domain model of the application.
        - `/repos` - Repositories to manipulate stored data.
        - `/services` - Defines domain logic using domain models.
- `/internal` - Private code not importing to other applications or libraries.
- `/pkg` - Public code exposed to others.
- `/test` - Additional external tests and test data.
- `/configs` - Configuration files.
- `/docs` - Design and user documents.
- `/examples` - Examples for our application and/or a public library.
- `/api` - API contract files (Swagger, Protocol Buffers, etc.).
    - `/proto` - Files used in Protocol Buffers/gRPC communication.
    - `/services` - Web API endpoints.
- `/web` - Web application-specific assets (static files, etc.).
- `/build` - Packaging and continuous integration (CI) files.
    - `/bin` - Binary and compilation files.
- `/scripts` - Scripts for analysis, installation, and so on.
    - `/docker` - Docker compose files to start the application.
    - `/idea` - IDE development scripts.
- `/vendor` - Application dependencies (for example, Go modules dependencies).

There’s no /src directory like in some other languages. The rationale is that /src is too generic; hence, this layout
favors directories such as /cmd, /internal, or /pkg.

> Source: Manning, 100 Go Mistakes and How to Avoid Them

## Security and compliance

> TODO: add security and compliance data...

## Useful resources

### Services

- [Shields.io](https://shields.io/)

### Guides

- [HABR - "Запускаем PostgreSQL в Docker: от простого к сложному" - 2021](https://habr.com/ru/articles/578744/)
- [HABR - "Разбираемся с пакетом Context в Golang" - 2019](https://habr.com/ru/companies/nixys/articles/461723/)
- [YouTube - "Swagger for Go REST APIs: Quick & Easy Documentation with Gin" - 2023](https://youtu.be/0b_N4y8_9iI?si=hqdJT9NGcBtQJbkK)
- [LogRocket - "Gin binding in Go: A tutorial with examples" - 2021](https://blog.logrocket.com/gin-binding-in-go-a-tutorial-with-examples/)
- [ZetCode - "Go CSV - read & write CSV" - 2023](https://zetcode.com/golang/csv/)
- [HABR - "Неочевидные проблемы с UUID ключами в PostgreSQL" - 2023](https://habr.com/ru/articles/747348/)