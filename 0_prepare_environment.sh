#!/bin/bash

set -e

echo "🔍 Detecting Linux Distribution..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "❌ It was not possible to determine the linux distribution (/etc/os-release is missing)."
    exit 1
fi

echo "🐧 DETECTED DISTRO: $DISTRO"

PYTHON_BIN="python3.11"

install_ubuntu() {
    echo "📦 Starting installation via APT (Ubuntu/Debian)..."
    sudo apt update
    sudo apt install -y software-properties-common curl git p7zip-full

    echo "🐍 Adding deadsnakes PPA for Python 3.11..."
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt update

    curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -

    sudo apt install -y nodejs psmisc lsof \
        python3.11 python3.11-venv python3.11-dev \
        build-essential
}

install_fedora() {
    echo "📦 Starting installation via DNF (Fedora/RHEL)..."

    curl -fsSL https://rpm.nodesource.com/setup_24.x | sudo bash -
    
    echo "🔧 Installing Python 3.11 and build tools..."
    sudo dnf install -y nodejs psmisc lsof git \
        python3.11 python3.11-devel \
        gcc gcc-c++ make p7zip p7zip-plugins
}

case $DISTRO in
    "ubuntu"|"debian"|"pop"|"linuxmint"|"kali")
        install_ubuntu
        ;;
    "fedora"|"rhel"|"centos"|"almalinux"|"rocky")
        install_fedora
        ;;
    *)
        echo "❌ Distro is not supported: $DISTRO"
        exit 1
        ;;
esac

echo "✅ Verifying Versions:"
echo "   Node:   $(node -v)"

if command -v python3.11 &> /dev/null; then
    echo "   Python: $(python3.11 --version)"
else
    echo "❌ Python 3.11 not found! Something went wrong."
    exit 1
fi

if [ -d "juice-shop" ]; then
    echo "📂 Folder 'juice-shop' already exists. Skipping git clone."
else
    echo "⬇️  Cloning Juice Shop..."
    git clone https://github.com/juice-shop/juice-shop.git --depth 1
fi

echo "🐍 Setting up Virtual Environment using $PYTHON_BIN..."
echo "   Ensuring pip is installed..."
$PYTHON_BIN -m ensurepip --default-pip || true

if [ -d "venv" ]; then
    rm -rf venv
fi

$PYTHON_BIN -m venv venv
source venv/bin/activate

echo "   Upgrading pip..."
pip install --upgrade pip

if [ -f "requirements.txt" ]; then
    echo "📦 Installing from requirements.txt..."
    pip install -r requirements.txt
else
    echo "⚠️  'requirements.txt' not found..."
fi

echo ""
echo "🚀 Setup finished successfully!"
echo "👉 To activate environment: source venv/bin/activate"