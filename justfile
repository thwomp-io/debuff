# Debuff: the whole loop, one command each. `just` lists them.
set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

# every check; a release must pass this with a clean tree
gate:
    scripts/gate.sh

# the same checks while you're mid-work (skips only the clean-tree step)
check:
    GATE_ALLOW_DIRTY=1 scripts/gate.sh

# build dist/debuff from this tree
build:
    scripts/build.sh

# set the version (then write its CHANGELOG entry, commit, and `just release`)
bump version:
    echo "{{version}}" > internal/version/VERSION

# tag VERSION and push; the pre-push hook runs the gate, and a failed push removes the tag
release:
    #!/usr/bin/env bash
    set -euo pipefail
    v=$(cat internal/version/VERSION)
    grep -q "^## \[$v\]" CHANGELOG.md || { echo "✗ CHANGELOG.md has no entry for $v"; exit 1; }
    [ -z "$(git status --porcelain)" ] || { echo "✗ working tree not clean: commit first"; exit 1; }
    git tag -a "v$v" -m "v$v"
    git push --follow-tags || { git tag -d "v$v"; echo "✗ push blocked, tag removed: fix forward"; exit 1; }
    echo "✓ released v$v"

# build, install, restart, require a healthy answer (else the previous binary goes back)
deploy: build
    scripts/deploy.sh

# scan this machine (findings stay in the private data dir)
scan:
    ~/.local/bin/debuff scan

# open the console, signed in
open:
    ~/.local/bin/debuff open

# put the previous binary back
rollback:
    scripts/rollback.sh

# is it up, and is what's running what's installed?
status:
    scripts/status.sh

# screenshot the running console into the private data dir (real findings stay out of the repo)
shot name="shot" viewport="desktop" theme="dark":
    scripts/shot.sh "http://127.0.0.1:8737/?token=$(cat ~/.local/state/debuff/token)" ~/.local/state/debuff/shots/{{name}}.png "{{viewport}}" "{{theme}}"

# build, serve the labeled sample data on throwaway state, shoot every layout into dist/shots/
shots:
    scripts/demo_shots.sh

# prove the gate stops each kind of fault
prove-gate:
    scripts/prove_gate.sh

# rehearse deploy, upgrade, bad build and rollback on a throwaway install
prove-deploy:
    scripts/prove_deploy.sh
