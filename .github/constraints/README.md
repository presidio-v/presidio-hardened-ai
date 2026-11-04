# Hash-pinned CI and release toolchains

These `*.txt` files are `--require-hashes` lockfiles for everything the CI and
release workflows install with `pip`. Pinning by hash satisfies the OpenSSF Scorecard
**Pinned-Dependencies** check and stops a compromised package index from
substituting the build backend, the metadata checker or the SBOM generator.

| File | Contents | Used by |
|---|---|---|
| `release-build.txt` | pip, build, hatchling | `publish.yml` (build) |
| `twine.txt` | twine | `publish.yml` (metadata check) |
| `cyclonedx.txt` | cyclonedx-bom | `publish.yml` (SBOM) |
| `runtime.txt` | the package's runtime dependencies | `publish.yml` (runtime environment the SBOM describes) |
| `ci-toolchain.txt` | pip, setuptools | every CI lane |
| `dev.txt` | the `dev` extra + `editable-backend.in` | `ci.yml`, `ci-mpc.yml` (`[mpc]` is a subset of `[dev]`), `ci-zk.yml` |
| `dev-torch.txt` | the `dev` and `torch` extras + `editable-backend.in` | `ci-torch.yml` |
| `zk-build.txt` | maturin | `ci-zk.yml` (native wheel build) |
| `fuzz.txt` | the `fuzz` extra + `editable-backend.in` (Python 3.12) | `fuzz.yml` |

Dependabot (`pip`, directory `/.github/constraints`) proposes pin and hash updates
weekly as one grouped PR.

## Regenerate

```bash
cd .github/constraints
for base in release-build twine cyclonedx; do
  uv pip compile --generate-hashes --universal --python-version 3.11 \
    --annotation-style=line "$base.in" -o "$base.txt"
done
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line ../../pyproject.toml -o runtime.txt
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line ci-toolchain.in -o ci-toolchain.txt
uv pip compile --generate-hashes --universal --python-version 3.12 \
  --annotation-style=line ../../pyproject.toml --extra fuzz editable-backend.in -o fuzz.txt
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line ../../pyproject.toml --extra dev editable-backend.in -o dev.txt
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line ../../pyproject.toml --extra dev --extra torch editable-backend.in -o dev-torch.txt
uv pip compile --generate-hashes --universal --python-version 3.11 \
  --annotation-style=line zk-build.in -o zk-build.txt
```

Add `--upgrade` to move existing pins to the newest allowed versions (without
it, uv keeps the pins already in the output file). Re-run the `runtime.txt` line
and the `dev*.txt` lines whenever `[project] dependencies` or the `dev`/`torch`
extras in `pyproject.toml` change.

Bump a tool by editing the matching `*.in` and re-running the loop. Keep the
hatchling range in `release-build.in` in step with `[build-system] requires` in
`pyproject.toml`.
