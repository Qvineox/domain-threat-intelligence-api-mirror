# System configuration

System configurations consists of 2 parts: static and dynamic configurations.
Static configuration is mostly obligatory, while dynamic is optional.

Static configuration can be stored in `config.static.json` or in environment.
Dynamic stored in `config.dynamic.json`, this file is watched by the system.

## Configuration examples

Static configuration:

```json
{
  "database": {
    "host": "xxx",
    "port": 5432,
    "name": "xxx",
    "user": "xxx",
    "password": "xxx",
    "timezone": "Europe/Moscow"
  },
  "http": {
    "host": "localhost",
    "port": 7090,
    "api": {
      "path": "/api/v1"
    },
    "swagger": {
      "enabled": true,
      "host": "localhost:7090",
      "version": "v0.0.1"
    },
    "security": {
      "tls": true,
      "domain": "qvineox.ru",
      "origins": [
        "http://localhost:5173",
        "https://domain-threat-intel.qvineox.ru"
      ]
    }
  }
}
```

Dynamic configuration:

```json
{
  "SMTP": {},
  "Integrations": {
    "Naumen": {
      "enabled": false,
      "ClientGroupID": 0,
      "ClientKey": "",
      "url": "",
      "BlacklistsService": {
        "AgreementID": 0,
        "SLM": 0,
        "CallType": "",
        "Types": null
      }
    }
  }
}
```