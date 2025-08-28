#!/usr/bin/env python3
"""
Debug script to isolate the exception handling issue
"""
import os
import sys
import traceback

def test_imports():
    """Test if all imports work correctly"""
    print("Testing imports...")
    try:
        import asyncio
        print("✓ asyncio")
        
        import aiohttp
        print("✓ aiohttp")
        
        import json
        print("✓ json")
        
        import base64
        print("✓ base64")
        
        import time
        print("✓ time")
        
        import hashlib
        print("✓ hashlib")
        
        import struct
        print("✓ struct")
        
        from typing import List, Optional
        print("✓ typing")
        
        print("All imports successful!")
        return True
        
    except Exception as e:
        print(f"Import error: {e}")
        traceback.print_exc()
        return False

def test_basic_syntax():
    """Test basic syntax by importing main module"""
    print("\nTesting main module syntax...")
    try:
        sys.path.insert(0, os.path.dirname(__file__))
        import main
        print("✓ main.py syntax is valid")
        return True
    except SyntaxError as e:
        print(f"Syntax error: {e}")
        return False
    except Exception as e:
        print(f"Import error: {e}")
        traceback.print_exc()
        return False

def test_environment():
    """Test environment variables"""
    print("\nTesting environment...")
    required_vars = ["RPC_HOST", "RPC_PORT", "RPC_USER", "RPC_PASS", "REWARD_ADDR"]
    
    for var in required_vars:
        value = os.getenv(var)
        if value:
            print(f"✓ {var}={value}")
        else:
            print(f"⚠ {var} not set (using default)")

if __name__ == "__main__":
    print("=== Stratum Server Debug ===\n")
    
    success = True
    success &= test_imports()
    success &= test_basic_syntax()
    test_environment()
    
    if success:
        print("\n✓ All tests passed! The issue might be runtime-related.")
        print("Try running with more verbose error reporting:")
        print("python3 -v main.py")
    else:
        print("\n✗ Found issues that need to be fixed first.")
