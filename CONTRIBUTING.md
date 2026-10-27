# Contributing to Insyte

Thanks for helping improve Insyte. This project is an evidence-first passive
intelligence platform, so contributions are judged on correctness, honesty of
the data model, and safety of outbound collection — not on feature count.

## Ground rules

- **Authorized use only.** Do not add exploitation, authentication bypass,
  brute-force, fuzzing, or payload-delivery features. Insyte stays read-only.
- **Evidence over guesses.** New detections must record provenance and
  confidence. Never present weak evidence as a confirmed finding.
- **No silent failures.** A module that cannot run must skip with a reason, not
  return an empty success.
- **Secrets never leave the server.** Never log, return, or persist a full
  secret value.
- **Respect provider terms and rate limits.** Use the shared rate limiter; do
  not add a second HTTP client.

## Development setup

See the [Local development](README.md#local-development) section of the README.

## Before opening a pull request

1. Create a feature branch:

   ```bash
   git checkout -b feat/my-change
   ```

2. Run the backend test suite:

   ```bash
   cd backend
   pytest -q
   ```

3. Run static checks:

   ```bash
   cd backend
   ruff check app/
   mypy app/
   bandit -r app/ -c pyproject.toml
   ```

4. Run the frontend checks:

   ```bash
   cd frontend
   npm ci
   npm run typecheck
   npm run build
   ```

5. Describe the change, its user-visible impact, and any security
   considerations in the pull request.

## Adding a module

1. Implement the module under `backend/app/modules/` using the existing
   `IntelligenceModule` contract.
2. Register it once in `backend/app/modules/registry.py` with its modes,
   dependencies, credential requirement, and ordering.
3. Add unit tests under `backend/tests/`.
4. If it needs a new provider, add the adapter under
   `backend/app/providers/` and declare its credential fields in
   `backend/app/core/credentials.py`.
5. Keep it GET/HEAD-only through the shared guarded HTTP client.

## Adding a provider

1. Implement the adapter using the existing provider base and rate limiter.
2. Declare credential fields, signup URL, and free-tier details in
   `backend/app/core/credentials.py`.
3. Make it degrade cleanly when unconfigured.
4. Add tests with `respx` or a stubbed transport — never call the real service
   from CI.

## Code style

- Backend: Ruff (line length 110), type hints, no comments that restate the
  code. Explain *why*, not *what*.
- Frontend: TypeScript strict, existing shadcn/ui primitives, TanStack Query for
  server state.
- Do not add a dependency unless the standard library or an existing dependency
  cannot do the job.

## Reporting security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the
[MIT License](LICENSE).
