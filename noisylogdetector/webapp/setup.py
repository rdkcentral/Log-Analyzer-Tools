#!/usr/bin/env python3
"""
Setup script for Log Quality Analyzer Web Application
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is 3.6 or higher"""
    if sys.version_info < (3, 6):
        print("❌ Python 3.6 or higher is required!")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version OK: {sys.version}")
    return True

def install_dependencies():
    """Install required Python packages"""
    print("\n📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Dependencies installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def check_rules_file():
    """Verify rules.yml exists in the repository root"""
    rules_path = Path(__file__).resolve().parent.parent / 'rules.yml'

    if not rules_path.exists():
        print("\n⚠️  Warning: rules.yml not found in repository root!")
        print(f"Expected location: {rules_path}")
        return False

    print("✅ Rules file found")
    return True

def create_directories():
    """Create necessary directories"""
    print("\n📁 Creating directories...")
    directories = ['uploads', 'static/css', 'static/js', 'templates']
    
    for dir_path in directories:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created/verified: {dir_path}")

def check_files():
    """Check if all required files exist"""
    print("\n🔍 Checking required files...")
    required_files = [
        'app.py',
        'log_analyzer.py',
        'requirements.txt',
        'templates/base.html',
        'templates/index.html',
        'templates/results.html',
        'templates/rules.html',
        'templates/history.html',
        'static/css/style.css',
        'static/js/app.js'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
            print(f"❌ Missing: {file_path}")
        else:
            print(f"✅ Found: {file_path}")
    
    if missing_files:
        print(f"\n❌ Missing {len(missing_files)} required files!")
        return False
    
    print("✅ All required files found!")
    return True

def main():
    """Main setup function"""
    print("🚀 Setting up Log Quality Analyzer Web Application...")
    print("=" * 55)
    
    # Change to webapp directory if not already there
    if not Path('app.py').exists() and Path('webapp/app.py').exists():
        os.chdir('webapp')
        print("📂 Changed to webapp directory")
    
    # Run setup checks
    if not check_python_version():
        sys.exit(1)
    
    create_directories()
    
    if not check_files():
        print("\n❌ Setup failed: Missing required files")
        sys.exit(1)
    
    if not check_rules_file():
        print("\n⚠️  Warning: Rules file issue detected")
    
    if not install_dependencies():
        print("\n❌ Setup failed: Could not install dependencies")
        sys.exit(1)
    
    print("\n" + "=" * 55)
    print("🎉 Setup completed successfully!")
    print("\n📋 To start the web application:")
    print("   python app.py")
    print("\n🌐 Once started, open your browser to:")
    print("   http://localhost:5000")
    print("\n💡 Features available:")
    print("   • File upload interface")
    print("   • Real-time analysis results")
    print("   • Downloadable HTML reports")
    print("   • Rule configuration editor")
    print("   • Analysis history")
    print("   • RESTful API endpoints")
    print("\n📚 API Endpoints:")
    print("   • POST /api/analyze - Analyze log file")
    print("   • GET /api/rules - Get current rules")
    print("   • PUT /api/rules - Update rules")
    print("   • GET /api/history - Get analysis history")

if __name__ == '__main__':
    main()
