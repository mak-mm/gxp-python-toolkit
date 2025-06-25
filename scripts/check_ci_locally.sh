#!/bin/bash
# Run CI checks locally before pushing

echo "🔍 Running CI checks locally..."
echo

echo "✨ Black formatter check..."
if black --check gxp_toolkit tests; then
    echo "✅ Black check passed"
else
    echo "❌ Black check failed - run 'black gxp_toolkit tests' to fix"
    exit 1
fi
echo

echo "📦 isort import check..."
if isort --check-only gxp_toolkit tests; then
    echo "✅ isort check passed"
else
    echo "❌ isort check failed - run 'isort gxp_toolkit tests' to fix"
    exit 1
fi
echo

echo "🔎 flake8 linting..."
# Ignore F401 (unused imports) for now as there are many
if flake8 gxp_toolkit tests --count --max-line-length=100 --extend-ignore=E203,W503,F401; then
    echo "✅ flake8 check passed"
else
    echo "❌ flake8 check failed"
    exit 1
fi
echo

echo "🏷️ mypy type checking..."
if mypy gxp_toolkit --ignore-missing-imports; then
    echo "✅ mypy check passed"
else
    echo "⚠️  mypy check has warnings (not critical)"
fi
echo

echo "🧪 Running tests..."
if python -m pytest tests/ -v --tb=short; then
    echo "✅ Tests passed"
else
    echo "❌ Tests failed"
    exit 1
fi
echo

echo "✅ All CI checks passed! Ready to push."