#!/bin/bash

# Pendege Launcher Script
# Script untuk menjalankan aplikasi Pendege dengan mudah

# (Tidak perlu cek direktori lagi)

echo "🚀 Starting Pendege - Penetration Testing Platform"
echo "=================================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 tidak ditemukan. Silakan install Python 3 terlebih dahulu."
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "📦 Python version: $PYTHON_VERSION"

# Check if we're in the right directory (harus ada folder platform dan file main.py di dalamnya)
if [ ! -f "platform/main.py" ]; then
    echo "❌ File platform/main.py tidak ditemukan. Pastikan Anda berada di direktori pendege."
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p platform/output

# Run basic test first
echo "🧪 Running basic tests..."
if python3 platform/test_basic.py; then
    echo "✅ Tests passed. Starting application..."
    echo ""
    # Run the main application
    python3 -m platform.main
else
    echo "❌ Tests failed. Please check the errors above."
    exit 1
fi 