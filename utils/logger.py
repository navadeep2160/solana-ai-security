import json
import os
from datetime import datetime
from pathlib import Path


LOG_DIR = Path("outputs/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def write_log(stage: str, data: dict):

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    file_path = LOG_DIR / f"{stage}_{timestamp}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "stage": stage,
                "timestamp": timestamp,
                "data": data
            },
            f,
            indent=2
        )

    return str(file_path)