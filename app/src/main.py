# src/main.py
#!/usr/bin/env python3
"""
Main entry point for Professional C2 Beacon Detector
"""

import sys
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent
sys.path.insert(0, str(src_path))

from core.detector import main

if __name__ == "__main__":
    main()
