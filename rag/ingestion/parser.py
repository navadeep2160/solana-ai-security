import os
from pathlib import Path

VALID_EXTENSIONS = [
    ".rs",
    ".md",
    ".txt",
    ".toml"
]

SKIP_DIRS = [
    ".git",
    "target",
    "node_modules"
]

def parse_repository(repo_path):

    for root, dirs, files in os.walk(repo_path):

        dirs[:] = [
            d for d in dirs
            if d not in SKIP_DIRS
        ]

        for file in files:

            path = Path(root) / file

            if path.suffix not in VALID_EXTENSIONS:
                continue

            try:

                content = path.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )

                yield {
                    "path": str(path),
                    "content": content
                }

            except:
                continue