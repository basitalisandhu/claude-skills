"""Synthetic FastMCP server for approval_gates.py tests. Parsed, never run."""
import os
import sqlite3

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

mcp = FastMCP("notes")


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def list_notes() -> list[str]:
    return sorted(os.listdir("notes"))


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))
def save_note(name: str, text: str) -> str:
    with open(f"notes/{name}.txt", "w", encoding="utf-8") as fh:
        fh.write(text)
    return "saved"


@mcp.tool()
def delete_note(name: str) -> str:
    os.remove(f"notes/{name}.txt")
    return "deleted"


@mcp.tool(name="purge_notes", annotations={"readOnlyHint": False, "destructiveHint": False})
def purge(reason: str) -> str:
    if not approve_purge(reason):
        return "cancelled"
    conn = sqlite3.connect("notes.db")
    conn.execute("DELETE FROM notes")
    return "purged"
