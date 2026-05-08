# Examples

Runnable apps showing how to integrate `sealed-env` into a real
project. Each example is **self-contained** and ships with a
pre-sealed `.env.sealed` plus the toy master key so you can clone
and run in 60 seconds.

> ⚠️ **The master keys checked into these examples are public on
> GitHub. Use them only for demoing.** For real projects, generate
> your own with `sealed-env init`.

## What's here

| Example | Stack | What it shows |
|---|---|---|
| [node-express](./node-express) | Node 20 + Express 4 | Auto-loading sealed env at startup with `import 'sealed-env/config'` — zero code change vs. plain dotenv. |
| [spring-boot](./spring-boot) | Java 17 + Spring Boot 3 | Spring Boot starter resolves `@Value("${KEY}")` directly from `.env.sealed` — no controller code change vs. plain `application.properties`. |

## Common shape

Every example has the same five files plus framework-specific code:

```
example-name/
├── README.md           ← run instructions, master key shown
├── .env.sealed         ← committed, encrypted (safe in git)
├── .env.local.example  ← copy to .env.local, contains the demo key
├── ...                 ← framework files
└── (no .env)           ← would be gitignored if it existed
```

The `.env.local.example` lets you `cp .env.local.example .env.local`
and immediately have the master key picked up by sealed-env's
auto-loader.

## What to do next after running the demo

```bash
# 1. Clone the repo locally
git clone https://github.com/davidalmeidac/sealed-env
cd sealed-env/examples/<your-stack>

# 2. Run the demo with the public toy key
cp .env.local.example .env.local
<install + run command from the example README>

# 3. Generate YOUR OWN master key for a real project
sealed-env init
# follow the next-steps printed by init
```

## Requirements

- **node-express:** Node 20 or newer
- **spring-boot:** Java 17 or newer + Maven 3.9+
- The `sealed-env` CLI installed globally is **optional** — useful
  if you want to inspect / re-seal:
  ```sh
  npm install -g sealed-env
  sealed-env get .env.sealed STRIPE_KEY
  ```
