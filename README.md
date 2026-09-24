# SecAuditorIA

API de auditoría de seguridad asistida por IA, con frontend en React. Un agente de IA (Groq + Semantic Kernel) analiza logs, configuraciones o reportes que le subís, contrasta el contenido contra una guía de buenas prácticas de seguridad, y devuelve hallazgos estructurados con severidad, recomendaciones, persistencia en base de datos, métricas y alertas automáticas.

Pensado como demo de **AppSec + AI Engineering**: no es "otro chatbot con OpenAI", sino un caso de uso realista de cómo proteger, monitorear y operar un endpoint que consume un LLM en producción.

> **Nota de contexto:** este proyecto está inspirado en patrones y prácticas de arquitectura que apliqué en un entorno profesional (autenticación, control de acceso, rate limiting, observabilidad y automatización de alertas sobre servicios que integran IA). Es una implementación propia, construida desde cero con herramientas gratuitas/open source, pensada como pieza de portfolio para demostrar ese conocimiento de forma pública y verificable.

## Las 4 capas técnicas

### 1. Inteligencia Artificial
- Orquestación con **Semantic Kernel**, conectado a **Groq** (API compatible con OpenAI) usando el modelo `openai/gpt-oss-120b`, con capa gratuita.
- RAG ligero: una guía de buenas prácticas de seguridad embebida se inyecta como contexto en el prompt, y el modelo contrasta el contenido subido contra ella.
- Salida **JSON estructurada** (`ResponseFormat: json_object`) en vez de texto libre, para obtener severidad, hallazgos y recomendaciones de forma confiable y parseable.

### 2. Seguridad por diseño
- **JWT** + **RBAC**: solo usuarios con el rol `SecurityAuditor` pueden invocar el agente.
- Secretos (API key de Groq, clave de firma JWT, URL de webhook) gestionados vía `dotnet user-secrets` en desarrollo y variables de entorno en el contenedor — nunca hardcodeados.
- Sanitización de archivos subidos: whitelist de extensiones, límite de tamaño, y el nombre de archivo se reduce con `Path.GetFileName()` antes de usarlo, neutralizando path traversal.
- El contenido del usuario se trata explícitamente como **datos**, nunca como instrucciones, en el system prompt — mitigación básica de prompt injection.
- CORS configurado explícitamente por origen (no wildcard).

### 3. Rendimiento y defensa financiera (AI Gateway)
- **Rate limiting** nativo de .NET (5 análisis/minuto por usuario) para proteger contra abuso y controlar el consumo de tokens de IA.
- **Métricas Prometheus** en `/metrics`: contador de análisis por resultado/severidad, histograma de latencia de las llamadas a Groq.

### 4. Automatización y persistencia
- **Webhook a n8n**: cuando un análisis detecta severidad "Crítica", se dispara automáticamente una notificación (simulando alerta a un canal de seguridad/DFIR). Diseñado *best-effort*: si n8n está caído, el análisis no falla.
- **EF Core + SQLite**: cada reporte generado se persiste con usuario, contenido analizado, resultado y severidad, para mantener un historial de auditorías (`GET /api/agent/reports`).

## Stack

**Backend:** .NET 10 / ASP.NET Core · Semantic Kernel + Groq · Entity Framework Core + SQLite · JWT Bearer Auth · prometheus-net · Docker

**Frontend:** React + TypeScript · Vite

## Cómo correrlo

### Backend (local)

```bash
cd src/Api
dotnet user-secrets set "Groq:ApiKey" "tu-api-key-de-groq"
dotnet user-secrets set "Jwt:Key" "$(openssl rand -base64 48)"
dotnet user-secrets set "Jwt:Issuer" "SecAuditAI"
dotnet user-secrets set "Jwt:Audience" "SecAuditAI.Client"
dotnet user-secrets set "N8n:WebhookUrl" "tu-url-de-webhook" # opcional

dotnet ef database update
dotnet run
```

La API queda en `http://localhost:5048`, con Swagger UI en `/swagger`.

### Backend (Docker)

```bash
docker build -t secaudit-ai .
docker run -d -p 8081:8080 \
  -e Groq__ApiKey="tu-api-key-de-groq" \
  -e Jwt__Key="$(openssl rand -base64 48)" \
  -e Jwt__Issuer="SecAuditAI" \
  -e Jwt__Audience="SecAuditAI.Client" \
  secaudit-ai
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Queda disponible en `http://localhost:5173` (o el próximo puerto libre). Usuario de demo: **admin** / **admin**.

## Uso vía API

**1. Login**

```bash
curl -X POST http://localhost:5048/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

**2. Analizar texto**

```bash
curl -X POST http://localhost:5048/api/agent/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"content":"El sistema guarda la contraseña de la base de datos en texto plano."}'
```

**3. Analizar un archivo** (`.txt`, `.log`, `.json`, `.conf`, `.yaml`, `.yml` — máx. 1 MB)

```bash
curl -X POST http://localhost:5048/api/agent/analyze-file \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@config.txt"
```

**4. Ver historial de reportes**

```bash
curl http://localhost:5048/api/agent/reports \
  -H "Authorization: Bearer $TOKEN"
```

## Próximos pasos

- Reemplazar el usuario hardcodeado por un sistema de usuarios real (ASP.NET Identity)
- Migrar de SQLite a PostgreSQL/SQL Server para producción
- Historial de reportes visible en el frontend
