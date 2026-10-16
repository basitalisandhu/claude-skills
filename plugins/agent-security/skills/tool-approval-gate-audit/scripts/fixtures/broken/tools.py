"""A valid file next to the broken one. Parsed, never run."""
from agents import function_tool


@function_tool
def get_status(service: str) -> str:
    return "ok"
