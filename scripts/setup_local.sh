#!/bin/bash

# Setup script for GxP Python Toolkit local development

echo "🏥 Setting up GxP Python Toolkit for local development..."
echo "=================================================="

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $python_version"

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install development dependencies
echo "📚 Installing development dependencies..."
pip install -r requirements-dev.txt

# Install package in development mode
echo "🔧 Installing gxp-toolkit in development mode..."
pip install -e .

# Run initial tests
echo "🧪 Running tests..."
pytest tests/ -v --tb=short

# Check code quality
echo "✨ Checking code quality..."
black --check gxp_toolkit tests || echo "⚠️  Some files need formatting (run: black gxp_toolkit tests)"
isort --check-only gxp_toolkit tests || echo "⚠️  Some imports need sorting (run: isort gxp_toolkit tests)"

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p audit_logs
mkdir -p docs/_build

echo ""
echo "✅ Setup complete!"
echo ""
echo "📝 Next steps:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Run the example: python examples/basic_usage.py"
echo "  3. Run tests: pytest"
echo "  4. Start developing!"
echo ""
echo "📚 Useful commands:"
echo "  - Run tests: pytest tests/ -v"
echo "  - Run specific test: pytest tests/test_soft_delete.py -v"
echo "  - Check coverage: pytest --cov=gxp_toolkit --cov-report=html"
echo "  - Format code: black gxp_toolkit tests"
echo "  - Sort imports: isort gxp_toolkit tests"
echo "  - Type check: mypy gxp_toolkit"
echo ""
echo "🔗 Documentation: file://$PWD/GXP_SOFTWARE_DEVELOPMENT_GUIDE.md"
