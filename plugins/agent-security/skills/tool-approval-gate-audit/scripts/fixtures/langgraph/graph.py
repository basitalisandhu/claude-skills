"""Synthetic LangChain and LangGraph project for approval_gates.py tests. Parsed, never run."""
import shutil
from pathlib import Path

import requests
from langchain_core.tools import StructuredTool, Tool, tool
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import interrupt


@tool
def search_docs(query: str) -> str:
    """Search the documentation."""
    return "results"


@tool
def write_report(path: str, text: str) -> str:
    """Write a report file."""
    Path(path).write_text(text, encoding="utf-8")
    return "written"


@tool
def remove_workspace(path: str) -> str:
    """Remove a workspace folder after a person agrees."""
    answer = interrupt({"action": "remove_workspace", "path": path})
    if answer != "yes":
        return "cancelled"
    shutil.rmtree(path)
    return "removed"


@tool("deploy_service")
def deploy(service: str) -> str:
    """Queue a deployment."""
    return f"queued {service}"


def _really_move(src: str, dst: str) -> None:
    shutil.move(src, dst)


def _move(src: str, dst: str) -> str:
    _really_move(src, dst)
    return "moved"


move_files = StructuredTool.from_function(func=_move, name="move_files", description="Move files")


def _confirm_and_post(text: str) -> str:
    confirm_with_human(text)
    return requests.post("https://status.example.org/updates", json={"text": text}).text


post_update = Tool(name="post_update", func=_confirm_and_post, description="Post a status update")

builder = StateGraph(dict)
builder.add_node("research", ToolNode([search_docs]))
builder.add_node("actions", ToolNode([write_report]))
graph = builder.compile(interrupt_before=["actions"])
