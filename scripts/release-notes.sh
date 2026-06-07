#!/usr/bin/env bash
#
# Generate GitHub Release notes for hypershunt.
#
# The notes have two parts:
#   1. "What's new in <version>" — derived from the Conventional Commit
#      subjects between the previous release tag and this one, so the delta
#      is authored by the commit log rather than by hand.
#   2. The product's current feature set, lifted verbatim from README.md.
#      The README is the single source of truth, so the recap never drifts
#      from what the project actually advertises.
#
# Usage: scripts/release-notes.sh [<version>]
#   <version>  release version without the leading 'v' (default: Cargo.toml).
#
# Honours GITHUB_REPOSITORY / GITHUB_REF_NAME when set (CI); otherwise falls
# back to the git origin remote and 'v<version>'.  Writes Markdown to stdout.

set -euo pipefail

# Run from the repo root so relative paths (README.md, Cargo.toml) and git
# resolve regardless of the caller's working directory.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

readme="README.md"

# --- version and tag range ------------------------------------------------

# Version comes from the argument, else the first version line in Cargo.toml.
version="${1:-}"
if [[ -z "$version" ]]; then
    version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
fi
current_tag="${GITHUB_REF_NAME:-v$version}"

# Previous release: the highest v* tag that isn't the current one.  Version
# sort orders semver correctly; dropping the current tag by exact match lets
# a re-run on an already-pushed tag still find its predecessor.
prev_tag=$(git tag --list 'v*' --sort=-version:refname \
    | grep -vFx "$current_tag" | head -n1 || true)

# Range end is the current tag if it exists locally, else HEAD — so a local
# "what would the next release look like?" run works before the tag is cut.
if git rev-parse -q --verify "refs/tags/$current_tag" >/dev/null; then
    range_end="$current_tag"
else
    range_end="HEAD"
fi
if [[ -n "$prev_tag" ]]; then
    range="$prev_tag..$range_end"
else
    range="$range_end"   # first release: walk the whole history
fi

# --- collect and bucket commits ------------------------------------------

breaking=() ; feats=() ; security=() ; fixes=() ; perfs=()

# type(scope)!: description  — anything without a recognised "type:" prefix
# is noise and stays out of the highlights.
cc_re='^([a-z]+)(\(([a-z0-9_-]+)\))?(!)?: (.+)$'

# --no-merges: squash-merge subjects already carry "(#N)"; the merge commits
# would otherwise list the same change twice.
#
# `|| [[ -n "$subject" ]]` processes the final line too: git's
# --pretty=format: emits no trailing newline, so the last subject would
# otherwise be read but dropped when read(1) reports EOF.
while IFS= read -r subject || [[ -n "$subject" ]]; do
    [[ "$subject" =~ $cc_re ]] || continue
    type="${BASH_REMATCH[1]}"
    scope="${BASH_REMATCH[3]}"
    bang="${BASH_REMATCH[4]}"
    desc="${BASH_REMATCH[5]}"

    line="- ${desc^}"   # tidy bullet: upper-case the first letter

    # A '!' marks a breaking change whatever the type, so surface it first.
    if [[ -n "$bang" ]]; then
        breaking+=("$line")
        continue
    fi

    case "$type" in
        feat)
            if [[ "$scope" == "security" ]]; then
                security+=("$line")
            else
                feats+=("$line")
            fi
            ;;
        fix)      fixes+=("$line") ;;
        perf)     perfs+=("$line") ;;
        security) security+=("$line") ;;
        *)        : ;;   # docs/test/refactor/chore/ci/build/release: omitted
    esac
done < <(git log --no-merges --pretty=format:'%s' "$range")

# --- render ---------------------------------------------------------------

# render <heading> <items...>  — emit a "### heading" block only when the
# bucket has items.  An empty array expands to nothing, so $# drops to 1.
highlights=0
render() {
    (( $# > 1 )) || return 0
    local heading="$1"; shift
    printf '### %s\n' "$heading"
    printf '%s\n' "$@"
    printf '\n'
    highlights=1
}

# emit_readme_section <heading>  — reproduce a "## heading" section verbatim,
# from its heading line through the line before the next "## " (or EOF).
emit_readme_section() {
    awk -v h="## $1" '
        $0 == h        { grab = 1; print; next }
        grab && /^## / { exit }
        grab           { print }
    ' "$readme"
}

# Owner/name for doc links: CI provides it; locally derive from the remote.
repo="${GITHUB_REPOSITORY:-}"
if [[ -z "$repo" ]]; then
    repo=$(git config --get remote.origin.url 2>/dev/null \
        | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##') || true
fi
ref="${GITHUB_REF_NAME:-$current_tag}"

{
    printf "## What's new in %s\n\n" "$version"
    [[ -z "$prev_tag" ]] && printf 'Initial release.\n\n'

    render "Breaking changes" "${breaking[@]}"
    render "New features"     "${feats[@]}"
    render "Security"         "${security[@]}"
    render "Fixes"            "${fixes[@]}"
    render "Performance"      "${perfs[@]}"

    (( highlights )) || printf 'Maintenance release.\n\n'

    emit_readme_section "Features"
    printf '\n'
    emit_readme_section "Standards"

    printf -- '---\n'
    if [[ -n "$repo" ]]; then
        printf 'See the [README](https://github.com/%s/blob/%s/README.md)' \
            "$repo" "$ref"
        printf ' and [docs](https://github.com/%s/tree/%s/docs) for' \
            "$repo" "$ref"
        printf ' configuration and usage.\n'
    else
        printf 'See the README and docs for configuration and usage.\n'
    fi
}
