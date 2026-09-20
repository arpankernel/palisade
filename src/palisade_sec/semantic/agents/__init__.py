"""Multi-agent analysis (Direction #1).

Phase 1a: build an AgentGraph from the IR - nodes are agents (with the tools
they hold and the capabilities those tools exercise), edges are handoffs
(agent A can hand control to agent B). Deterministic and offline; it makes no
network calls and no judgments, so it stays in the keyless core.

This is the substrate the cross-agent injection finding (PI-AGENT-HANDOFF,
Phase 1b) will build on. It respects the precision-first contract: it only
records what the IR states explicitly.
"""

from palisade_sec.semantic.agents.graph import (
    AgentEdge,
    AgentGraph,
    AgentNode,
    build_agent_graph,
)

__all__ = ["AgentEdge", "AgentGraph", "AgentNode", "build_agent_graph"]
