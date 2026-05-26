from typing import TypedDict, Optional, Dict, Any


class PipelineState(TypedDict):
    contract: str

    # scanner output
    findings: Dict[str, Any]

    # retrieval context
    context: str

    # patching
    patched_code: str

    # validation
    build_success: bool
    build_error: str

    # iteration control
    iteration: int