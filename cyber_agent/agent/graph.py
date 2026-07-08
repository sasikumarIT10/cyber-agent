"""LangGraph agent construction and execution."""

import logging
from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode, tools_condition

from agent.state import AgentState
from agent.prompts import SYSTEM_PROMPT
from agent.skills_loader import find_relevant_skills
from tools.cve_lookup import cve_search, cve_details
from tools.port_scanner import scan_ports
from tools.dns_recon import dns_lookup, reverse_dns, dns_zone_info
from tools.ip_reputation import check_ip_reputation, check_domain_reputation
from tools.log_analyzer import analyze_logs
from tools.hash_checker import check_file_hash
from tools.network_utils import whois_lookup, geolocation_lookup
from tools.cloud_aws import guardduty_list_findings, guardduty_get_threat_intel, aws_security_hub_summary
from tools.cloud_gcp import gcp_scc_list_findings, gcp_scc_vulnerability_report, gcp_asset_inventory
from tools.cloud_k8s import k8s_rbac_audit, k8s_pod_security_audit, k8s_exposed_services, k8s_image_vulnerability_check
from tools.cloud_iam import aws_iam_audit, gcp_iam_audit, cloud_iam_comparison

logger = logging.getLogger(__name__)

ALL_TOOLS = [
    # Core security tools
    cve_search,
    cve_details,
    scan_ports,
    dns_lookup,
    reverse_dns,
    dns_zone_info,
    check_ip_reputation,
    check_domain_reputation,
    analyze_logs,
    check_file_hash,
    whois_lookup,
    geolocation_lookup,
    # Cloud security tools - AWS
    guardduty_list_findings,
    guardduty_get_threat_intel,
    aws_security_hub_summary,
    # Cloud security tools - GCP
    gcp_scc_list_findings,
    gcp_scc_vulnerability_report,
    gcp_asset_inventory,
    # Cloud security tools - Kubernetes
    k8s_rbac_audit,
    k8s_pod_security_audit,
    k8s_exposed_services,
    k8s_image_vulnerability_check,
    # Cloud IAM
    aws_iam_audit,
    gcp_iam_audit,
    cloud_iam_comparison,
]

# Module-level cached agent instance (reuse across calls)
_cached_agent = None


def create_agent():
    """Create and return the cybersecurity agent graph. Cached after first call."""
    global _cached_agent
    if _cached_agent is not None:
        return _cached_agent

    import config

    llm = ChatAnthropic(
        model=config.AGENT_MODEL,
        api_key=config.ANTHROPIC_API_KEY,
        max_tokens=config.AGENT_MAX_TOKENS,
        temperature=config.AGENT_TEMPERATURE,
    )

    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    def agent_node(state: AgentState):
        """The main reasoning node that decides which tools to call."""
        messages = state["messages"]

        system_content = SYSTEM_PROMPT
        query_text = ""
        for m in reversed(messages):
            if isinstance(m, HumanMessage):
                query_text = m.content if isinstance(m.content, str) else str(m.content)
                break

        if query_text:
            skills_context = find_relevant_skills(query_text, max_skills=3)
            if skills_context:
                system_content += (
                    "\n\n## Relevant Skills Library Reference\n"
                    "The following procedures from the cybersecurity skills library "
                    "may help. Use them as reference for your analysis:\n\n"
                    + skills_context
                )

        if not any(isinstance(m, SystemMessage) for m in messages):
            messages = [SystemMessage(content=system_content)] + messages

        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    tool_node = ToolNode(ALL_TOOLS)

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)

    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", tools_condition)
    graph.add_edge("tools", "agent")

    _cached_agent = graph.compile()
    return _cached_agent


def _build_messages(query, history=None):
    """Build message list from query and conversation history."""
    messages = []
    if history:
        for msg in history:
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "user":
                messages.append(HumanMessage(content=content))
            elif role == "assistant":
                messages.append(AIMessage(content=content))

    messages.append(HumanMessage(content=query))
    return messages


def run_agent(query, history=None):
    """Run the agent with a query and return the final response."""
    agent = create_agent()
    messages = _build_messages(query, history)

    initial_state = {
        "messages": messages,
        "task_summary": "",
        "findings": [],
    }

    try:
        result = agent.invoke(initial_state)
        final_message = result["messages"][-1]
        return final_message.content
    except Exception as e:
        logger.error("Agent execution failed: %s", e)
        raise


async def run_agent_stream(query, history=None):
    """Run the agent with streaming output."""
    agent = create_agent()
    messages = _build_messages(query, history)

    initial_state = {
        "messages": messages,
        "task_summary": "",
        "findings": [],
    }

    async for event in agent.astream_events(initial_state, version="v2"):
        kind = event["event"]
        if kind == "on_chat_model_stream":
            content = event["data"]["chunk"].content
            if content:
                yield content
