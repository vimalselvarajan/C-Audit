# Load the repository's .env into the current shell.
#
#     source tools/load-env.sh
#
# Deliberately has no shebang and is not executable: it must be *sourced*, not
# run. A subprocess that sets a variable and exits has done nothing, so being
# executed is a mistake worth reporting rather than a no-op.
#
# caudit never reads .env itself -- there is no dotenv dependency and no
# load_dotenv call anywhere in src/. This script is the whole mechanism: the
# shell exports the values and caudit reads the environment at call time, as
# documented in my_docs/guides/setup.md section 5.
#
# The file is *executed* by `.` below, so it must contain shell assignments and
# nothing else. That is inherent to `set -a; . file` and is why .env.example
# contains only comments and one assignment.

# --------------------------------------------------------------- sourced?
# When bash executes a script, BASH_SOURCE[0] equals $0; when it sources one,
# they differ. This check is bash-only on purpose. In a shell without
# BASH_SOURCE the two are equal whether sourced or not, and acting on that
# false positive would run the `exit` below in the user's interactive shell --
# closing their terminal to warn them about a mistake they did not make.
if [ -n "${BASH_VERSION:-}" ] && [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "load-env.sh must be sourced, not executed -- run:" >&2
    echo "    source tools/load-env.sh" >&2
    # Genuinely a subprocess here, so exiting affects nothing but itself.
    exit 64
fi

# ------------------------------------------------------------------ paths
# Resolved from this script's own location, so sourcing works from any
# subdirectory of the repository.
_caudit_root="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
_caudit_env="$_caudit_root/.env"

if [ ! -f "$_caudit_env" ]; then
    echo "no .env at $_caudit_env" >&2
    echo "Create one from the template:" >&2
    echo "    cp '$_caudit_root/.env.example' '$_caudit_env'" >&2
    unset _caudit_root _caudit_env
    return 1
fi

# ------------------------------------------------------------------- load
# Restore the caller's allexport rather than clearing it: a bare `set +a` would
# silently turn off an option the user had switched on themselves.
_caudit_had_allexport=0
case $- in
    *a*) _caudit_had_allexport=1 ;;
esac

set -a
# shellcheck disable=SC1090
. "$_caudit_env"
_caudit_status=$?
if [ "$_caudit_had_allexport" -eq 0 ]; then
    set +a
fi

if [ "$_caudit_status" -ne 0 ]; then
    echo "$_caudit_env is not valid shell -- it must hold KEY=value lines only" >&2
    echo "Quote any value containing spaces. See .env.example" >&2
    unset _caudit_root _caudit_env _caudit_had_allexport _caudit_status
    return 1
fi

# ------------------------------------------------------------------ check
# Report which variable is set, never its value: the name is the useful part,
# and echoing the key would put it in terminal scrollback and in whatever
# captures that.
if [ -n "${GEMINI_API_KEY:-}" ]; then
    echo "loaded $_caudit_env -- GEMINI_API_KEY is set"
elif [ -n "${GOOGLE_API_KEY:-}" ]; then
    echo "loaded $_caudit_env -- GOOGLE_API_KEY is set (GEMINI_API_KEY is not)"
else
    echo "loaded $_caudit_env but neither GEMINI_API_KEY nor GOOGLE_API_KEY is set" >&2
    echo "Add one to $_caudit_env -- see .env.example" >&2
    _caudit_status=1
fi

# A sourced script shares the caller's shell, so leaving these behind would
# litter the user's environment. The status has to outlive the unset, hence
# the branch rather than `unset ...; return $_caudit_status`.
unset _caudit_root _caudit_env _caudit_had_allexport
if [ "$_caudit_status" -eq 0 ]; then
    unset _caudit_status
    return 0
fi
unset _caudit_status
return 1
