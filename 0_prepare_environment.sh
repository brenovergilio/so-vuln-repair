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

# --- INSTALLATION FUNCTIONS ---

install_ubuntu() {
    echo "📦 Starting instalation via APT..."
    sudo apt update

    sudo apt install -y curl git python3-pip
    
    curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
    
    sudo apt install -y nodejs psmisc lsof
}

install_fedora() {
    echo "📦 Starting instalation via DNF..."

    curl -fsSL https://rpm.nodesource.com/setup_24.x | sudo bash -
    
    sudo dnf install -y nodejs psmisc lsof git python3-pip
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
        echo "   Please, install nodejs, psmisc, lsof, git and python3-pip manually."
        exit 1
        ;;
esac

echo "✅ Verifying Node and NPM versions:"
echo "   Node: $(node -v)"
echo "   NPM:  $(npm -v)"

if [ -d "juice-shop" ]; then
    echo "📂 Folder 'juice-shop' already exists. Skipping git clone."
else
    echo "⬇️  Cloning Juice Shop..."
    git clone https://github.com/juice-shop/juice-shop.git --depth 1
fi

if [ -f "requirements.txt" ]; then
    echo "🐍 Installing Python dependencies..."
    
    python3 -m venv venv
    source venv/bin/activate

    pip3 install -r requirements.txt || \
    pip3 install -r requirements.txt --break-system-packages
else
    echo "⚠️ 'requirements.txt' not found."
fi

echo "🚀 Setup finished!"