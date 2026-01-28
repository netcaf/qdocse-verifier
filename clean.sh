#!/bin/bash
# deep_clean.sh - Deep clean a pytest project, including caches, temp files, and optionally Git repo

PROJECT_DIR=$(pwd)
echo "Starting deep cleanup in $PROJECT_DIR ..."

# ------------------------
# 1. Python / pytest caches
# ------------------------
echo "Cleaning Python and pytest caches..."
find "$PROJECT_DIR" -type d -name "__pycache__" -exec rm -rf {} +
find "$PROJECT_DIR" -type f -name "*.pyc" -exec rm -f {} +
find "$PROJECT_DIR" -type f -name "*.pyo" -exec rm -f {} +
find "$PROJECT_DIR" -type d -name ".pytest_cache" -exec rm -rf {} +
find "$PROJECT_DIR" -type f -name ".coverage" -exec rm -f {} +
find "$PROJECT_DIR" -type d -name ".cache" -exec rm -rf {} +
find "$PROJECT_DIR" -type d -name ".tox" -exec rm -rf {} +
find "$PROJECT_DIR" -type d -name "*.egg-info" -exec rm -rf {} +
find "$PROJECT_DIR" -type d -name "dist" -exec rm -rf {} +
find "$PROJECT_DIR" -type d -name "build" -exec rm -rf {} +
find "$PROJECT_DIR" -type d -name ".mypy_cache" -exec rm -rf {} +
find "$PROJECT_DIR" -type f -name "*.log" -exec rm -f {} +
find "$PROJECT_DIR" -type f -name "*.tmp" -exec rm -f {} +

# ------------------------
# 2. IDE / editor temporary files
# ------------------------
echo "Cleaning IDE/editor files..."
find "$PROJECT_DIR" -type d -name ".vscode" -exec rm -rf {} +
find "$PROJECT_DIR" -type d -name ".idea" -exec rm -rf {} +
find "$PROJECT_DIR" -type d -name ".ropeproject" -exec rm -rf {} +
find "$PROJECT_DIR" -type f -name "*.swp" -exec rm -f {} +
find "$PROJECT_DIR" -type f -name "*.swo" -exec rm -f {} +
find "$PROJECT_DIR" -type f -name "*.bak" -exec rm -f {} +

# ------------------------
# 3. Git temporary files (safe)
# ------------------------
echo "Cleaning Git files..."
rm -rf "$PROJECT_DIR/.git"

echo "Deep cleanup completed."
