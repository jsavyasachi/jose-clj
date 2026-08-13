# Contributing to jose-clj

Send bug reports, fixes, and focused feature contributions for `jose-clj`.

## Before you start

- For work beyond a trivial fix, **open an issue first**. This lets us agree on
  the approach before you invest time.
- Check existing issues and pull requests to avoid duplicate work.

## Project layout

A `deps.edn` library with one namespace: `vector-search.core` - the
embedded HNSW index API (`index`, `add!`, `search`, `remove!`, `get-item`,
`size`, `save` / `load-index`) over hnswlib-core.

Hot paths operate on primitive float arrays and must stay reflection-free.
Expected failures throw `ex-info` with a `:vector-search/error` key.

## Building and testing

Requires JDK 17+.

```bash
clojure -M:test            # full suite (Kaocha)
clojure -M:1.11:test       # Clojure 1.11 matrix cell
clojure -M:1.12:test       # Clojure 1.12 matrix cell
clojure -T:build jar       # build a jar
```

The full suite is deterministic and self-contained. It uses a seeded RNG for
the recall smoke test. There is nothing to download.

Requirements for a mergeable change:

- **Tests first.** Add or update tests for the behavior you change; for a bug
  fix, include a regression test that fails before your fix and passes after.
- **Green build.** `clojure -M:test` passes and `src` compiles with **zero**
  reflection warnings (`*warn-on-reflection*` is on).
- **One scope.** Keep each pull request to one logical change.

## Commits and pull requests

- Follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:` …).
- Keep the subject in the imperative mood and under ~72 characters.
- Update `CHANGELOG.md` when your change is user-visible.
- Rebase on the latest `main` before opening the pull request.

## License

By contributing, you agree that your contributions will be licensed under the
Eclipse Public License 2.0, the same license as this project (see `LICENSE`).
