"""Synthetic project where every consequential tool is gated. Parsed, never run."""
import requests
from agents import function_tool
from langchain_core.tools import tool
from langgraph.types import interrupt


@function_tool
def get_order(order_id: str) -> dict:
    return requests.get(f"https://shop.example.com/orders/{order_id}").json()


@function_tool(needs_approval=True)
def refund_order(order_id: str, amount: float) -> str:
    return requests.post("https://shop.example.com/refunds", json={"order": order_id, "amount": amount}).text


@tool
def cancel_subscription(subscription_id: str) -> str:
    """Cancel a subscription after a person agrees."""
    decision = interrupt({"action": "cancel_subscription", "subscription_id": subscription_id})
    if decision != "approve":
        return "kept"
    return requests.delete(f"https://shop.example.com/subscriptions/{subscription_id}").text
