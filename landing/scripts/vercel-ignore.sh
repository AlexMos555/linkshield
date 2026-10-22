#!/bin/sh
# Vercel "Ignored Build Step" for the landing project (landing/vercel.json ->
# ignoreCommand). Vercel runs it from the project's Root Directory (landing/)
# before every build:
#   exit 0 -> skip: the deployment is canceled and shows as "Ignored"
#   exit 1 -> build as usual
#
# Every push to every branch reaches this project, and most of them (API, ML,
# extension, mobile app) cannot change the site. The rule: skip only when git
# says, for certain, that nothing the landing build reads differs from the
# commit Vercel last built successfully. Anything uncertain builds: no previous
# deployment, a commit that cannot be fetched, a failing git command.
#
# A deployment this script cancels still counts toward Vercel's daily
# deployment quota (100 on Hobby). So landing/vercel.json also sets
# git.deploymentEnabled to main only: other branches get no deployment at all,
# and this script in practice decides only for pushes to main. Its preview
# rules below stay for the day previews are turned back on.
#
# The base to compare with:
#   VERCEL_GIT_PREVIOUS_SHA  the last SUCCESSFUL deployment of this project and
#                            branch (a skipped one is not successful, so skips
#                            never move it, and nothing can be missed between
#                            two builds). Vercel sets it only when an Ignored
#                            Build Step exists, and leaves it empty on a
#                            branch's first deployment.
#   empty, production        build.
#   empty, preview           compare with the tip of main: a branch whose
#                            landing files equal main's would only preview
#                            what is already live. Without this, a branch that
#                            never touched the landing would never have a
#                            successful deployment, and would build on every
#                            push.
# The comparison is by content (git diff of two trees), not by history, so it
# also holds after a revert or a force-push.
#
# Tested by landing/e2e/vercel-ignore.spec.ts.

PRODUCTION_BRANCH=main

say() { printf 'vercel-ignore: %s\n' "$*"; }
build() { say "BUILD - $*"; exit 1; }
skip() { say "SKIP - $*"; exit 0; }
short() { printf '%.7s' "$1"; }

# Never wait for a password: Vercel's build container has no one to type it.
export GIT_TERMINAL_PROMPT=0

with_timeout() {
  if command -v timeout >/dev/null 2>&1; then timeout 60 "$@"; else "$@"; fi
}

has_commit() { git cat-file -e "$1^{commit}" 2>/dev/null; }

# The repository's public GitHub URL, as a second place to fetch from when the
# clone has no usable "origin" remote. Empty outside a GitHub deployment.
github_url() {
  [ "${VERCEL_GIT_PROVIDER:-}" = github ] || return 0
  for part in "${VERCEL_GIT_REPO_OWNER:-}" "${VERCEL_GIT_REPO_SLUG:-}"; do
    case $part in '' | *[!A-Za-z0-9._-]*) return 0 ;; esac
  done
  printf 'https://github.com/%s/%s.git' "$VERCEL_GIT_REPO_OWNER" "$VERCEL_GIT_REPO_SLUG"
}

# fetch DEPTH REFSPEC. Vercel clones only the last few commits, so an older
# base has to be fetched before git can compare with it.
fetch() {
  for remote in origin $(github_url); do
    if with_timeout git fetch --quiet --no-tags --depth="$1" "$remote" "$2" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

command -v git >/dev/null 2>&1 || build "git is not available, so what changed is unknown"
top=$(git rev-parse --show-toplevel 2>/dev/null) || build "not inside a git checkout"
cd "$top" || build "cannot enter the repository root $top"
head=$(git rev-parse --verify --quiet 'HEAD^{commit}') || build "HEAD is not a commit"

prev=${VERCEL_GIT_PREVIOUS_SHA:-}
if [ -n "$prev" ]; then
  case $prev in
    *[!0-9a-fA-F]*) build "VERCEL_GIT_PREVIOUS_SHA is not a commit SHA: $prev" ;;
  esac
  [ "$prev" != "$head" ] || build "same commit as the last successful deployment (a redeploy)"
  has_commit "$prev" || fetch 50 "$prev"
  has_commit "$prev" || build "the last successful deployment $(short "$prev") is not in the clone and could not be fetched"
  base=$prev
  against="since the last successful deployment"
elif [ "${VERCEL_ENV:-}" = preview ]; then
  fetch 1 "+refs/heads/$PRODUCTION_BRANCH:refs/vercel-ignore/$PRODUCTION_BRANCH" ||
    build "no successful deployment of this branch yet, and $PRODUCTION_BRANCH could not be fetched to compare with"
  base=$(git rev-parse --verify --quiet "refs/vercel-ignore/$PRODUCTION_BRANCH^{commit}") ||
    build "no successful deployment of this branch yet, and $PRODUCTION_BRANCH could not be read to compare with"
  against="compared with $PRODUCTION_BRANCH"
else
  build "no previous successful deployment to compare with (VERCEL_GIT_PREVIOUS_SHA is empty, VERCEL_ENV=${VERCEL_ENV:-unset})"
fi

# Everything `npm install` and `npm run build` read for the landing, from the
# repository root:
#   landing                         the site: app, messages, public, e2e (type-
#                                   checked by next build), vercel.json, this script
#   packages/api-client, api-types  workspace packages the site imports
#   package.json, package-lock.json root manifest; installCommand installs here
#   .npmrc                          npm's project config, read by that install
#   packages/email-templates/package.json, mobile/package.json
#                                   the other workspaces' manifests, resolved by
#                                   the same install into the shared node_modules
#   mobile/scripts/apply-patches.js, mobile/patches
#                                   mobile's postinstall, which the same install
#                                   runs: it patches packages in the shared root
#                                   node_modules. A workspace that gains another
#                                   install script adds the files it reads here
#                                   (landing/e2e/vercel-ignore.spec.ts fails
#                                   until it does).
#   scripts/sync-addin.cjs, email-plugin-outlook
#                                   prebuild copies the add-in into public/outlook
#   docs/benchmarks/latest.json     read at build time by lib/benchmark.ts
#   .gitignore                      Tailwind's class scan skips git-ignored files
# Not here because the build never reads them: api/, ml/, extension*/,
# packages/extension-core, packages/i18n-strings (landing/messages is generated
# from it and committed), the mobile app's code and its other scripts, other
# docs, .github/.
set -- \
  landing \
  packages/api-client \
  packages/api-types \
  package.json \
  package-lock.json \
  .npmrc \
  packages/email-templates/package.json \
  mobile/package.json \
  mobile/scripts/apply-patches.js \
  mobile/patches \
  scripts/sync-addin.cjs \
  email-plugin-outlook \
  docs/benchmarks/latest.json \
  .gitignore

range="$(short "$base")..$(short "$head")"
git diff --quiet --no-ext-diff "$base" "$head" -- "$@"
status=$?
case $status in
  0) skip "nothing the landing build reads changed $against ($range)" ;;
  1)
    changed=$(git diff --name-only --no-ext-diff "$base" "$head" -- "$@" | wc -l | tr -d ' ')
    build "$changed landing file(s) changed $against ($range)"
    ;;
  *) build "git diff failed with exit code $status ($range)" ;;
esac
