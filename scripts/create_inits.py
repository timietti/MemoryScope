# This script creates all required __init__.py files
# Run once: python scripts/create_inits.py

import os

packages = [
    "backend",
    "backend/api",
    "backend/api/routers",
    "backend/api/middleware",
    "backend/core",
    "backend/core/agent",
    "backend/core/plugins",
    "backend/core/plugins/parsers",
    "backend/db",
    "backend/db/models",
    "backend/workers",
    "backend/utils",
    "backend/schemas",
]

for pkg in packages:
    init = os.path.join(pkg, "__init__.py")
    os.makedirs(pkg, exist_ok=True)
    if not os.path.exists(init):
        open(init, "w").close()
        print(f"Created {init}")
    else:
        print(f"Exists  {init}")
