# Spring Boot example

Minimal Spring Boot 3 app that reads its config from a sealed
`.env` file via the `sealed-env-spring-boot-starter`. Demonstrates
the **zero-code-change** integration: `@Value("${KEY}")` and
`Environment.getProperty("KEY")` work transparently — same code as
plain `application.properties`.

## Run it in 60 seconds

```bash
cd examples/spring-boot
cp .env.local.example .env.local
SEALED_ENV_KEY=$(grep SEALED_ENV_KEY .env.local | cut -d= -f2) \
  ./mvnw spring-boot:run
```

> Note: Spring Boot doesn't auto-load `.env.local` the way the Node
> CLI does. You explicitly export `SEALED_ENV_KEY` before starting
> the JVM. In production it'd come from your orchestrator
> (Kubernetes Secret, ECS task definition, systemd EnvironmentFile,
> etc.) — never from a flat file on disk.

Or with plain Maven if you have it installed:

```bash
SEALED_ENV_KEY=$(grep SEALED_ENV_KEY .env.local | cut -d= -f2) \
  mvn spring-boot:run
```

Then in another terminal:

```bash
curl http://localhost:8080
```

You should see the decrypted secrets in the JSON response.

## What's happening

```
   ┌──────────────────┐         ┌──────────────────┐
   │ SEALED_ENV_KEY   │         │ .env.sealed      │
   │ (env var)        │         │ (ciphertext,     │
   │                  │         │  in repo)        │
   └────────┬─────────┘         └────────┬─────────┘
            │                            │
            │      both consumed by      │
            │  SealedEnvEnvironment-     │
            │     PostProcessor          │
            ▼                            ▼
        ┌────────────────────────────────────┐
        │ Spring Environment populated with: │
        │   DATABASE_URL=postgresql://...    │
        │   STRIPE_KEY=sk_test_demo...       │
        │   JWT_SECRET=demo-jwt-secret...    │
        │   PORT=3000                        │
        └────────────────────────────────────┘
                       │
                       ▼
              @Value("${...}") resolves
              normally from any bean
```

The starter runs as an `EnvironmentPostProcessor`, which means it
fires **before** any other Spring property source is bound. Your
beans see the decrypted values as if they were in
`application.properties` from day one.

## The demo master key

```
SEALED_ENV_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

This key is **public on GitHub** and exists only to make the example
runnable. The decrypted values (`STRIPE_KEY=sk_test_demo...` etc.) are
intentionally fake. **Never reuse this key in a real project.**

## Adapt for your own Spring Boot project

```xml
<!-- 1. Add the starter to pom.xml -->
<dependency>
    <groupId>io.github.davidalmeidac</groupId>
    <artifactId>sealed-env-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

```bash
# 2. From your project root, generate a key + encrypt your .env:
sealed-env init
sealed-env encrypt .env

# 3. In production (K8s, ECS, systemd…) set SEALED_ENV_KEY as an env var.
#    The starter picks it up automatically. No code changes.
```

```yaml
# 4. (Optional) tune the starter behaviour in application.yml:
sealed-env:
  path: .env.sealed       # default
  enabled: true           # default
  fail-fast: true         # recommended in production
  override: false         # default — explicit properties win
```

## Files in this example

```
spring-boot/
├── .env.sealed             ← committed (encrypted, safe in git)
├── .env.local.example      ← copy to .env.local (master key)
├── pom.xml
├── src/main/java/io/example/Application.java
├── src/main/resources/application.yml
└── README.md               ← this file
```
