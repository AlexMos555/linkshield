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
# Environment variables are build input too: Next.js inlines NEXT_PUBLIC_* at
# build time, and the runbooks apply NEXT_PUBLIC_STRIPE_LIVE, _BILLING_ENABLED
# or a new APK URL with a dashboard Redeploy. Vercel runs this step on a
# Redeploy as well (unless "Use project's Ignore Build Step" is unticked in
# the Redeploy dialog), and nothing in it tells a Redeploy from a push:
# VERCEL_GIT_PREVIOUS_SHA is still the last successful deployment, so a
# Redeploy of the newest row, a push this step had canceled, compared the
# same two commits and was canceled again. So before a skip, the build's
# NEXT_PUBLIC_* stamp (scripts/build-env-stamp.cjs) is compared with the one
# the deployment it would skip to publishes at /build-env.txt: production's
# for production and for a branch's first preview, the branch URL's for a
# later preview (behind Deployment Protection that cannot be read, so it
# builds). Different, or unreadable: build. Server-only variables are not in
# the stamp: to apply one, Redeploy with that box unticked.
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

# Its sibling, found before the cd below (Vercel runs `sh scripts/vercel-ignore.sh`).
stamp_script=$(cd "$(dirname "$0")" && pwd)/build-env-stamp.cjs

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
  # The site that deployment serves: a preview's at the branch URL.
  if [ "${VERCEL_ENV:-}" = preview ]; then live=${VERCEL_BRANCH_URL:-}; else live=${VERCEL_PROJECT_PRODUCTION_URL:-}; fi
elif [ "${VERCEL_ENV:-}" = preview ]; then
  fetch 1 "+refs/heads/$PRODUCTION_BRANCH:refs/vercel-ignore/$PRODUCTION_BRANCH" ||
    build "no successful deployment of this branch yet, and $PRODUCTION_BRANCH could not be fetched to compare with"
  base=$(git rev-parse --verify --quiet "refs/vercel-ignore/$PRODUCTION_BRANCH^{commit}") ||
    build "no successful deployment of this branch yet, and $PRODUCTION_BRANCH could not be read to compare with"
  against="compared with $PRODUCTION_BRANCH"
  live=${VERCEL_PROJECT_PRODUCTION_URL:-}
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
#   docs/benchmarks/latest.json     read at build time by lib/benchmark.ts, a
#                                   symlink: the report it points to is
#                                   added below
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

# latest.json is a symlink to the dated report the benchmark last published,
# and git compares a symlink by the name it holds: a report rewritten in place
# (a second run the same day, a fix to a published snapshot) left the link
# byte for byte the same while the numbers on the site changed. So the report
# it names, at either end, is compared too. A link that leaves
# docs/benchmarks/ is nothing this script can vouch for: build.
LATEST=docs/benchmarks/latest.json
for rev in "$base" "$head"; do
  entry=$(git ls-tree "$rev" -- "$LATEST") || build "git could not list $LATEST at $(short "$rev")"
  case $entry in 120000\ *) ;; *) continue ;; esac
  target=$(git cat-file blob "$rev:$LATEST") || build "git could not read the $LATEST link at $(short "$rev")"
  case $target in
    '' | .* | */* | *[!A-Za-z0-9._-]*) build "$LATEST at $(short "$rev") points outside docs/benchmarks/ ($target)" ;;
  esac
  set -- "$@" "docs/benchmarks/$target"
done

range="$(short "$base")..$(short "$head")"
git diff --quiet --no-ext-diff "$base" "$head" -- "$@"
status=$?
case $status in
  0)
    # Same files; the same NEXT_PUBLIC_* values too? (see the header)
    command -v node >/dev/null 2>&1 ||
      build "nothing the landing build reads changed $against ($range), but node is not available to compare NEXT_PUBLIC_* with the live site"
    # It prints one line, and exits 0 only when the stamps match.
    if env_check=$(node "$stamp_script" --compare "$live" 2>/dev/null); then
      skip "nothing the landing build reads changed $against ($range), and $env_check. To build anyway: Redeploy with \"Use project's Ignore Build Step\" unticked"
    fi
    build "nothing the landing build reads changed $against ($range), but ${env_check:-the NEXT_PUBLIC_* comparison failed}"
    ;;
  1)
    changed=$(git diff --name-only --no-ext-diff "$base" "$head" -- "$@" | wc -l | tr -d ' ')
    build "$changed landing file(s) changed $against ($range)"
    ;;
  *) build "git diff failed with exit code $status ($range)" ;;
esac
