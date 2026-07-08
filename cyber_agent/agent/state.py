"""Agent state definition for LangGraph."""

from typing import Annotated, TypedDict
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class AgentState(TypedDict):
    """State maintained across the agent's execution graph."""
    messages: Annotated[list[BaseMessage], add_messages]
    task_summary: str
    findings: list[str]
