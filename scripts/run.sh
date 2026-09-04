#!/usr/bin/env sh
set -u

case "$0" in
    */*) SCRIPT_LOCATION=${0%/*} ;;
    *) SCRIPT_LOCATION=. ;;
esac
SCRIPT_DIR=$(CDPATH= cd -- "$SCRIPT_LOCATION" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if [ -n "${PYTHON:-}" ]; then
    PYTHON_BIN=$PYTHON
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN=python
else
    echo "ERROR: Python 3 was not found. Install Python or set PYTHON to its executable path." >&2
    exit 127
fi

usage() {
    cat <<'EOF'
Usage: scripts/run.sh COMMAND [ARGUMENTS]

Commands:
  analyze        Analyze a TJ directory or supported archives
  verify         Verify a saved analysis bundle
  slices         Build analytical slices from a saved bundle
  report         Build the overview PDF report
  test           Run analyzer and PDF test suites
  test-analyzer  Run analyzer tests only
  test-report    Run PDF module tests only
  check-data     Validate committed JSON, CSV and SQLite fixture contracts

Arguments after COMMAND are passed unchanged to the corresponding Python CLI.
Set PYTHON to a Python 3 executable path to override automatic detection.
EOF
}

if [ "$#" -eq 0 ]; then
    usage
    exit 0
fi

COMMAND=$1
shift
cd "$REPO_ROOT" || exit 1

case "$COMMAND" in
    help|--help|-h)
        usage
        ;;
    analyze)
        exec "$PYTHON_BIN" -B tools/one_c_tj_analyzer/analyze_1c_tj.py "$@"
        ;;
    verify)
        exec "$PYTHON_BIN" -B tools/one_c_tj_analyzer/verify_analysis.py "$@"
        ;;
    slices)
        exec "$PYTHON_BIN" -B tools/one_c_tj_analyzer/derive_slices.py "$@"
        ;;
    report)
        exec "$PYTHON_BIN" -B tools/one_c_tj_report/build_report.py "$@"
        ;;
    test)
        "$PYTHON_BIN" -B -m unittest discover -s tools/one_c_tj_analyzer/tests -v &&
            "$PYTHON_BIN" -B -m unittest discover -s tools/one_c_tj_report/tests -v
        ;;
    test-analyzer)
        exec "$PYTHON_BIN" -B -m unittest discover -s tools/one_c_tj_analyzer/tests -v
        ;;
    test-report)
        exec "$PYTHON_BIN" -B -m unittest discover -s tools/one_c_tj_report/tests -v
        ;;
    check-data)
        exec "$PYTHON_BIN" -B -m unittest discover -s tools/one_c_tj_report/tests -p test_saved_contract.py -v
        ;;
    *)
        echo "ERROR: Unknown command '$COMMAND'." >&2
        usage >&2
        exit 2
        ;;
esac
