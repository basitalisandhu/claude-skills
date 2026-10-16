"""Synthetic OpenAI Agents SDK project for approval_gates.py tests. Parsed, never run."""
import subprocess

import requests
from agents import Agent, FunctionTool, function_tool

ASK = True


def is_large(ctx, params, call_id):
    return params.get("amount", 0) > 100


@function_tool
def get_weather(city: str) -> str:
    return requests.get("https://api.example.com/weather", params={"city": city}).text


@function_tool(needs_approval=True)
def send_invoice(customer_id: str, amount: float) -> str:
    return requests.post("https://billing.example.com/invoices", json={"customer": customer_id, "amount": amount}).text


@function_tool
def run_tests(path: str) -> str:
    return subprocess.run(["pytest", path], capture_output=True, text=True).stdout


@function_tool(needs_approval="yes")
def delete_branch(name: str) -> str:
    return requests.delete(f"https://git.example.com/branches/{name}").text


@function_tool(needs_approval=is_large)
def transfer_credits(account: str, amount: int) -> str:
    return requests.post("https://ledger.example.com/transfer", json={"to": account, "amount": amount}).text


@function_tool(needs_approval=False)
def publish_notes(text: str) -> str:
    return text


@function_tool(needs_approval=ASK)
def list_invoices(customer_id: str) -> list:
    return []


async def _archive(ctx, args):
    with open("archive.log", "a", encoding="utf-8") as fh:
        fh.write(args)
    return "ok"


archive_tool = FunctionTool(
    name="archive_record",
    description="Append a record to the archive.",
    params_json_schema={},
    on_invoke_tool=_archive,
)

agent = Agent(name="Billing", tools=[get_weather, send_invoice, run_tests, delete_branch, transfer_credits,
                                     publish_notes, list_invoices, archive_tool])
