# AGENTS.md — TourIstmo

## Architecture

Two independent subsystems in one repo:

- **`app/`, `components/`, `lib/`** — Next.js 15 (App Router) frontend, React 19, Tailwind CSS v4 (not v3)
- **`src/`** — Python 3.11 AI orchestration backend (LLM clients, RAG pipeline, inference engine)

They share no code, no shared types, no interop. Treat them as separate projects.

## Frontend commands

```bash
pnpm dev          # next dev --turbopack
pnpm build        # next build
pnpm lint         # next lint (ESLint)
```

No `test` or `typecheck` scripts exist. `tsconfig.json` has `"strict": true` but type-checking only runs at build time.

## Python commands

```bash
# One-time setup
source scripts/setup_env.sh     # creates .venv, installs deps

# Run tests (unit only by default)
source .venv/bin/activate && pytest tests

# Run integration tests (requires live API keys)
RUN_API_TESTS=1 pytest tests

# Full test suite via Docker
docker compose up --build
```

## Python config & env

- Model selection via `config/model_config.yaml` (default: gpt-4o-mini via OpenAI)
- Requires `.env` with `OPENAI_API_KEY` and/or `ANTHROPIC_API_KEY`
- Integration tests are skipped unless `RUN_API_TESTS=1` is set
- RAG vector store and embeddings live in `data/` (gitignored except `.gitkeep` files)

## Frontend conventions

- **Import alias:** `@/*` maps to repo root (`./*`), not `src/`. Import components as `@/components/navbar`, data as `@/lib/data`.
- **Tailwind CSS v4** — uses `@theme inline { … }` in `app/globals.css` for custom tokens. No `tailwind.config.ts`. PostCSS via `@tailwindcss/postcss`.
- **Fonts:** Inter + Poppins loaded via `next/font/google` in `app/layout.tsx`, exposed as CSS variables `--font-inter` / `--font-poppins`.
- **All UI copy is Spanish.** No i18n, no language toggles.
- **No icon library** — all icons are inline SVG. Do not add icon npm packages.
- **Static data** lives in `lib/data.ts`. There is no API/database for the frontend yet.
- **Images from Unsplash** — only `images.unsplash.com` and `developer.apple.com` are allowed in `next.config.ts` `remotePatterns`.

## Design system

Full brand guide lives in `README.md` (colors, typography, spacing, radius, shadows, animations, copy voice). The `SKILL.md` and `ui_kits/web/` directory contain reference JSX components for the navbar, footer, cards, hero, login form, and dashboard. Prefer matching those patterns when building new UI.
