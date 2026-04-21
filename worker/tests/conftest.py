"""
Pytest configuration for worker tests.

Run from the worker/ directory:
    pytest tests/ -v

Or inside the dev container:
    docker compose -f docker-compose.yml exec worker pytest tests/ -v
"""
import sys
import os

# Make sure "app" is importable when running pytest from worker/
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
