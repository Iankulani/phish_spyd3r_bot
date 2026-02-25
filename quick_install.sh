#!/bin/bash
# quick_install.sh

echo "🐟 Phish-Spyd3r-Bot Quick Install"
echo "=================================="

# Check Python version
python_version=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
if (( $(echo "$python_version < 3.7" | bc -l) )); then
    echo "❌ Python 3.7+ required. Found: $python_version"
    exit 1
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📥 Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Check for external tools
echo "🔍 Checking external tools..."
tools=("nmap" "curl" "wget" "dig" "traceroute" "nikto" "crunch")
missing_tools=()

for tool in "${tools[@]}"; do
    if command -v $tool &> /dev/null; then
        echo "  ✅ $tool found"
    else
        echo "  ❌ $tool missing"
        missing_tools+=($tool)
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo ""
    echo "⚠️  Missing tools detected. Install with:"
    echo "  sudo apt install ${missing_tools[*]}  # Debian/Ubuntu"
    echo "  sudo pacman -S ${missing_tools[*]}     # Arch"
    echo "  brew install ${missing_tools[*]}       # macOS"
fi

echo ""
echo "✅ Installation complete!"
echo "Run: python phish_spyd3r_bot.py"