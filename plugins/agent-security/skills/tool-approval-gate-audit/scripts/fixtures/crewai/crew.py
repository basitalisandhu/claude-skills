"""Synthetic crewAI project for approval_gates.py tests. Parsed, never run."""
import os
import smtplib

from crewai import Agent, Task
from crewai.tools import BaseTool, tool


class SendNewsletterTool(BaseTool):
    name: str = "send_newsletter"
    description: str = "Send the weekly newsletter to subscribers."

    def _run(self, subject: str, body: str) -> str:
        with smtplib.SMTP("mail.example.com") as smtp:
            smtp.send_message(build_message(subject, body))
        return "sent"


class CleanupTool(BaseTool):
    name: str = "cleanup_cache"
    description: str = "Delete a cached file."

    def _run(self, path: str) -> str:
        input(f"Delete {path}? ")
        os.remove(path)
        return "done"


@tool("lookup_customer")
def lookup_customer(email: str) -> str:
    """Find a customer record."""
    return "record"


@tool("update_crm")
def update_crm(record_id: str, status: str) -> str:
    """Change a customer's status."""
    if not request_approval(f"update {record_id} to {status}"):
        return "refused"
    db.execute("UPDATE customers SET status = ? WHERE id = ?", (status, record_id))
    return "updated"


writer = Agent(role="Writer", goal="Send the newsletter", backstory="Example", tools=[SendNewsletterTool()])
newsletter = Task(
    description="Send this week's newsletter",
    expected_output="Confirmation",
    agent=writer,
    tools=[SendNewsletterTool()],
    human_input=True,
)
