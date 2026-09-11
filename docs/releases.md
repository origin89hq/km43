# Releasing this repository

Follow the [Origin89 release standard](https://github.com/origin89hq/engineering/blob/main/docs/releases.md).

- Packages: `@origin89/km43`, the TypeScript bindings in `packages/km43`. The
  Rust crate `km43` is published to crates.io by hand with `cargo publish`,
  not by this workflow.
- Default branch: `main`, and `.changeset/config.json` says so.
- Workflow: `.github/workflows/origin89-release.yml`. npm's trusted publisher
  for `@origin89/km43` must name this repository and this filename.
- Validation: `pnpm check` lints, type-checks and builds `packages/km43/dist`,
  which is what the tarball carries, and the package's `prepack` builds it
  again and copies the two license texts in from the repository root on any
  `pack` or `publish`, so a hand publish from a clean checkout ships neither an
  empty tarball nor one without its terms. The gate also packs it dry to show what would
  ship.
- Generated files: none change with a version. `packages/km43/src/generated.ts`
  is written by `cargo xtask registry` from `protocol.toml`, not by a release.
- Extra release assets: none.
- Exceptions: none.

Contributors run `pnpm changeset` and include the note in their PR.
Maintainers review and merge the generated release PR when ready to publish.
Run the check workflow on `changeset-release/main` before merging if the
release PR was created using the default `GITHUB_TOKEN`.

The first publication of a package that does not yet exist on npm cannot use
trusted publishing, which is configured on an existing package: publish the
first version by hand with a granular token, register the publisher, then let
the workflow take over.
