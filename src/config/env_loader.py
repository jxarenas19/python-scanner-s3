"""
Environment Loader
Loads environment variables from .env file
"""

import os
from pathlib import Path


def load_env_file():
    """Load environment variables from .env file"""
    # Find .env file in project root
    current_dir = Path(__file__).parent
    project_root = current_dir.parent.parent  # Go up two levels to project root
    env_file = project_root / ".env"

    if env_file.exists():
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue

                # Parse key=value pairs
                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip()

                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]

                    # Set environment variable (override if already exists to prioritize .env file)
                    os.environ[key] = value


# Load environment variables when this module is imported
load_env_file()
