#!/usr/bin/env bash
# STIG Assessor Launcher (Bash/Linux)

# Exit on error
set -e

# Resolve script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Mode: gui (default), web, cli
MODE=${1:-gui}
shift || true
ARGS="$@"

# Discover Python
PYTHON_CMD=""
VENV_DIR="$SCRIPT_DIR/venv"
WHEELS_DIR="$SCRIPT_DIR/wheels"

# 1. Prioritize local venv if it exists
if [ -d "$VENV_DIR" ]; then
    if [ -f "$VENV_DIR/bin/python3" ]; then
        PYTHON_CMD="$VENV_DIR/bin/python3"
        echo "Local venv detected and active."
    elif [ -f "$VENV_DIR/bin/python" ]; then
        PYTHON_CMD="$VENV_DIR/bin/python"
        echo "Local venv detected and active."
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    if [ -f "$SCRIPT_DIR/python/bin/python3" ]; then
        PYTHON_CMD="$SCRIPT_DIR/python/bin/python3"
    elif command -v python3 &>/dev/null; then
        SYSTEM_PYTHON="python3"
    elif command -v python &>/dev/null; then
        SYSTEM_PYTHON="python"
    fi

    if [ -n "$SYSTEM_PYTHON" ]; then
        # If we have a system python but no local venv/lib, offer to create one from wheels
        if [ ! -d "$SCRIPT_DIR/lib" ] && [ -d "$WHEELS_DIR" ]; then
            echo "Dependencies not found, but bundled wheels detected."
            read -p "Create a local virtual environment (venv) using system Python? [Y/n] " confirm
            if [[ $confirm != "n" && $confirm != "N" ]]; then
                echo "Creating venv..."
                $SYSTEM_PYTHON -m venv "$VENV_DIR"
                PYTHON_CMD="$VENV_DIR/bin/python3"
                echo "Installing dependencies from wheels..."
                $PYTHON_CMD -m pip install --no-index --find-links="$WHEELS_DIR" defusedxml sv-ttk
                echo "Setup complete."
            else
                PYTHON_CMD="$SYSTEM_PYTHON"
            fi
        else
            PYTHON_CMD="$SYSTEM_PYTHON"
        fi
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "Error: Python not found. Please install Python or use the full bundled version."
    exit 1
fi

# Configure PYTHONPATH for vendored dependencies if present
LIB_DIR="$SCRIPT_DIR/lib"
if [ -d "$LIB_DIR" ]; then
    if [ -z "$PYTHONPATH" ]; then
        export PYTHONPATH="$LIB_DIR"
    else
        export PYTHONPATH="$LIB_DIR:$PYTHONPATH"
    fi
    echo "Local 'lib' detected, added to PYTHONPATH."
fi

echo "Using Python: $(which $PYTHON_CMD 2>/dev/null || echo $PYTHON_CMD)"

case $MODE in
    gui)
        echo "Starting STIG Assessor GUI..."
        $PYTHON_CMD -m stig_assessor.ui.cli --gui
        ;;
    web)
        echo "Starting STIG Assessor Web Server on http://127.0.0.1:8080 ..."
        echo "Press Ctrl+C to stop."
        $PYTHON_CMD -m stig_assessor.ui.cli --web
        ;;
    cli)
        if [ -n "$ARGS" ]; then
            $PYTHON_CMD -m stig_assessor.ui.cli $ARGS
        else
            $PYTHON_CMD -m stig_assessor.ui.cli --help
        fi
        ;;
    *)
        echo "Usage: $0 {gui|web|cli} [arguments]"
        exit 1
        ;;
esac
