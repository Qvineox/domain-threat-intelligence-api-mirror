# Domain Threat Intelligence API

Master's thesis in Cybersecurity on malicious domain detection. Central core application.
Provides API for Web application and users. Controls scanning agents, report analysis and more.

This project is mirrored from GitLab.

Links:

- [Main project on GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-api)
- [Mirror on GitHub](https://github.com/Qvineox/domain-threat-intelligence-api-mirror)
- [Master's thesis paper RU](https://cloud.qvineox.ru/index.php/s/wLg8bncwQWz9Tff)

Ecosystem:

- Hub ([GitLab](https://gitlab.qvineox.ru/masters/domain-threat-intelligence-hub) / [GitHub](https://github.com/Qvineox/domain-threat-intelligence-hub-mirror))
- Agent ([GitLab](https://gitlab.qvineox.ru/masters/domain_threat_intelligence) / [GitHub](https://github.com/Qvineox/domain-threat-intelligence-agent-mirror))

## Setup and deployment

This project is cloud based and uses Docker Compose as it's primary and only supported method of deployment.
Docker-compose files are available in [docker](scripts%2Fdocker) directory.

All development scripts are available in [scripts](scripts) directory.

### Environment

Following variables are used in application. These variables are also mapped in automated GitLab CI/CD:

| Environment Variable | GitLab CI Variable | Description               | Example values    |
|----------------------|--------------------|---------------------------|-------------------|
| db_host              | $DB_HOST           | Database host             | 0.0.0.0, database |
| db_port              | $DB_PORT           | Database port             | 5432              |
| db_user              | $DB_USER           | Database user             | user              |
| db_pass              | $DB_PASS           | Database user password    | password123!      |
| db_name              | $DB_NAME           | Default database name     | database_name     |
| db_timezone          | $DB_TZ             | Default database timezone | Europe/Moscow     |

### Continuous integration using GitLab

All the files required to run automated GitLab CI are located in [build](build) directory.

## Project structure

The Go language maintainer has no strong convention about structuring a project in Go. However, one layout has emerged
over the years: [project-layout](https://github.com/golang-standards/project-layout).
If our project is small enough (only a few files), or if our organization has already created its standard, it may not
be worth using or migrating to project-layout. Other-wise, it might be worth considering. Let’s look at this layout and
see what the main directories are:

- `/cmd` - The main source files. The main.go of a foo application should live in /cmd/foo/main.go.
    - `/core` - Main application logic. Holds all business processes.
        - `/entities` - Core domain model of the application.
        - `/repos` - Repositories to manipulate stored data.
        - `/services` - Defines domain logic using domain models.
- `/internal` - Private code that we don’t want others importing for their applications or libraries.
- `/pkg` - Public code that we want to expose to others.
- `/test` - Additional external tests and test data.
- `/configs` - Configuration files.
- `/docs` - Design and user documents.
- `/examples` - Examples for our application and/or a public library.
- `/api` - API contract files (Swagger, Protocol Buffers, etc.).
    - `/proto` - Files used in Protocol Buffers/gRPC communication.
    - `/services` - Web API endpoints.
- `/web` - Web application-specific assets (static files, etc.).
- `/build` - Packaging and continuous integration (CI) files.
- `/scripts` - Scripts for analysis, installation, and so on.
- `/vendor` - Application dependencies (for example, Go modules dependencies).

There’s no /src directory like in some other languages. The rationale is that /src is too generic; hence, this layout
favors directories such as /cmd, /internal, or /pkg.

> Source: Manning, 100 Go Mistakes and How to Avoid Them

## Useful resources

### Guides

- [HABR - "Запускаем PostgreSQL в Docker: от простого к сложному" - 2021](https://habr.com/ru/articles/578744/)