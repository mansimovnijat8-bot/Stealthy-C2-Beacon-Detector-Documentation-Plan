# run_dashboard.py
#!/usr/bin/env python3
"""
Script to run the C2 Detection Dashboard
"""

import subprocess
import sys
import os

def install_requirements():
    """Install required packages"""
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "streamlit", "plotly", "pandas"
        ])
        print("✅ Required packages installed successfully")
    except subprocess.CalledProcessError:
        print("❌ Failed to install packages")
        sys.exit(1)

def run_dashboard():
    """Run the Streamlit dashboard"""
    try:
        # Create viz directory if it doesn't exist
        viz_dir = os.path.join("src", "viz")
        os.makedirs(viz_dir, exist_ok=True)
        
        # Check if dashboard file exists
        dashboard_file = os.path.join(viz_dir, "dashboard.py")
        if not os.path.exists(dashboard_file):
            print("❌ Dashboard file not found. Please create src/viz/dashboard.py")
            sys.exit(1)
        
        # Run Streamlit
        print("🚀 Starting C2 Detection Dashboard...")
        print("📊 Dashboard will open in your browser at http://localhost:8501")
        print("⏹️  Press Ctrl+C to stop the dashboard")
        
        subprocess.check_call([
            sys.executable, "-m", "streamlit", "run", dashboard_file
        ])
        
    except subprocess.CalledProcessError:
        print("❌ Failed to start dashboard")
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped")

if __name__ == "__main__":
    install_requirements()
    run_dashboard()
