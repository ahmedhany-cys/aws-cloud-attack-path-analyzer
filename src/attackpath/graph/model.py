"""Graph data structures.

A small purpose-built directed multigraph is used instead of a general graph
library: the analyzer needs typed edges carrying evidence, deterministic ordering
for reproducible reports, hard size limits, and nothing else. Keeping the core free
of third-party dependencies is a deliberate supply-chain decision.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from attackpath.config import Limits
from attackpath.exceptions import LimitExceededError
from attackpath.models.environment import Sensitivity
from attackpath.models.finding import Confidence, Evidence, EvidenceKind, GraphSummary
from attackpath.tri import Tri


class NodeType(str, Enum):
    ACCOUNT = "account"
    USER = "user"
    GROUP = "group"
    ROLE = "role"
    MANAGED_POLICY = "managed-policy"
    S3_BUCKET = "s3-bucket"
    LAMBDA_FUNCTION = "lambda-function"
    EC2_INSTANCE = "ec2-instance"
    EXTERNAL_ACCOUNT = "external-account"
    EXTERNAL_PRINCIPAL = "external-principal"
    ANONYMOUS = "anonymous"
    INTERNET = "internet"
    SERVICE = "service"


class EdgeType(str, Enum):
    MEMBER_OF = "member-of"
    HAS_POLICY = "has-policy"
    TRUSTS = "trusts"
    EXECUTES_AS = "executes-as"
    RUNS_AS = "runs-as"
    NETWORK_EXPOSED = "network-exposed"
    CAN_ASSUME = "can-assume"
    CAN_ACCESS = "can-access"


#: Edge types along which a path moves from one identity (or foothold) to another:
#: assuming a role, a function executing as its role, an instance running with its
#: instance-profile role, and the internet reaching an instance's open ports.
TRANSITION_EDGE_TYPES: frozenset[EdgeType] = frozenset(
    {EdgeType.CAN_ASSUME, EdgeType.EXECUTES_AS, EdgeType.RUNS_AS, EdgeType.NETWORK_EXPOSED}
)

#: Node types that can start an attack path.
SOURCE_NODE_TYPES: frozenset[NodeType] = frozenset(
    {
        NodeType.USER,
        NodeType.ROLE,
        NodeType.LAMBDA_FUNCTION,
        NodeType.EC2_INSTANCE,
        NodeType.EXTERNAL_ACCOUNT,
        NodeType.EXTERNAL_PRINCIPAL,
        NodeType.ANONYMOUS,
        NodeType.INTERNET,
    }
)

_EVIDENCE_ORDER = {
    EvidenceKind.OBSERVED: 0,
    EvidenceKind.INFERRED: 1,
    EvidenceKind.HYPOTHETICAL: 2,
    EvidenceKind.INDETERMINATE: 3,
}
_CONFIDENCE_ORDER = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


def weakest_evidence(kinds: Iterable[EvidenceKind]) -> EvidenceKind:
    return max(kinds, key=lambda k: _EVIDENCE_ORDER[k], default=EvidenceKind.OBSERVED)


def lowest_confidence(values: Iterable[Confidence]) -> Confidence:
    return max(values, key=lambda c: _CONFIDENCE_ORDER[c], default=Confidence.HIGH)


@dataclass
class Node:
    id: str
    type: NodeType
    label: str
    account_id: str | None = None
    sensitivity: Sensitivity = Sensitivity.UNKNOWN
    is_admin: Tri = Tri.FALSE
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def is_principal(self) -> bool:
        return self.type in (NodeType.USER, NodeType.ROLE)

    @property
    def privilege(self) -> float:
        """Estimated privilege level 0..1 (set by the builder; 1.0 for admin)."""
        value = self.attrs.get("privilege")
        return float(value) if isinstance(value, int | float) else 0.0


@dataclass
class Edge:
    source: str
    target: str
    type: EdgeType
    label: str
    confidence: Confidence = Confidence.HIGH
    evidence_kind: EvidenceKind = EvidenceKind.OBSERVED
    evidence: tuple[Evidence, ...] = ()
    preconditions: tuple[str, ...] = ()
    traversable: bool = True
    attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> tuple[str, str, str, str]:
        return (self.source, self.target, self.type.value, self.label)

    @property
    def is_transition(self) -> bool:
        return self.type in TRANSITION_EDGE_TYPES


class AttackGraph:
    """Directed multigraph with typed, evidence-carrying edges and hard size limits."""

    def __init__(self, limits: Limits | None = None) -> None:
        self.limits = limits or Limits()
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._out: dict[str, list[Edge]] = {}
        self._in: dict[str, list[Edge]] = {}
        self._keys: set[tuple[str, str, str, str]] = set()

    # ---- construction ----------------------------------------------------
    def add_node(self, node: Node) -> Node:
        existing = self.nodes.get(node.id)
        if existing is not None:
            return existing
        if len(self.nodes) >= self.limits.max_graph_nodes:
            raise LimitExceededError(
                f"graph exceeds the limit of {self.limits.max_graph_nodes} nodes"
            )
        self.nodes[node.id] = node
        self._out.setdefault(node.id, [])
        self._in.setdefault(node.id, [])
        return node

    def add_edge(self, edge: Edge) -> bool:
        if edge.source not in self.nodes or edge.target not in self.nodes:
            raise KeyError(f"edge endpoints must exist: {edge.source} -> {edge.target}")
        if edge.key in self._keys:
            return False
        if len(self.edges) >= self.limits.max_graph_edges:
            raise LimitExceededError(
                f"graph exceeds the limit of {self.limits.max_graph_edges} edges"
            )
        self._keys.add(edge.key)
        self.edges.append(edge)
        self._out[edge.source].append(edge)
        self._in[edge.target].append(edge)
        return True

    # ---- queries ---------------------------------------------------------
    def node(self, node_id: str) -> Node | None:
        return self.nodes.get(node_id)

    def out_edges(self, node_id: str, edge_type: EdgeType | None = None) -> list[Edge]:
        edges = self._out.get(node_id, [])
        return [e for e in edges if edge_type is None or e.type is edge_type]

    def in_edges(self, node_id: str, edge_type: EdgeType | None = None) -> list[Edge]:
        edges = self._in.get(node_id, [])
        return [e for e in edges if edge_type is None or e.type is edge_type]

    def nodes_of_type(self, *types: NodeType) -> Iterator[Node]:
        wanted = set(types)
        for node in self.nodes.values():
            if node.type in wanted:
                yield node

    def edges_of_type(self, *types: EdgeType) -> Iterator[Edge]:
        wanted = set(types)
        for edge in self.edges:
            if edge.type in wanted:
                yield edge

    def summary(self, paths_found: int = 0, paths_truncated: bool = False) -> GraphSummary:
        by_node: dict[str, int] = {}
        for node in self.nodes.values():
            by_node[node.type.value] = by_node.get(node.type.value, 0) + 1
        by_edge: dict[str, int] = {}
        for edge in self.edges:
            by_edge[edge.type.value] = by_edge.get(edge.type.value, 0) + 1
        return GraphSummary(
            node_count=len(self.nodes),
            edge_count=len(self.edges),
            nodes_by_type=dict(sorted(by_node.items())),
            edges_by_type=dict(sorted(by_edge.items())),
            paths_found=paths_found,
            paths_truncated=paths_truncated,
        )

    # ---- export ----------------------------------------------------------
    def to_dot(
        self,
        node_ids: Iterable[str] | None = None,
        *,
        edge_types: Iterable[EdgeType] | None = None,
        max_nodes: int = 400,
    ) -> str:
        """Render (a subset of) the graph as Graphviz DOT with escaped labels."""
        selected = set(node_ids) if node_ids is not None else set(self.nodes)
        allowed_edges = set(edge_types) if edge_types is not None else set(EdgeType)
        lines = [
            "digraph attackpath {",
            "  rankdir=LR;",
            '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10];',
            '  edge [fontname="Helvetica", fontsize=9];',
        ]
        count = 0
        for node_id in sorted(selected):
            node = self.nodes.get(node_id)
            if node is None:
                continue
            count += 1
            if count > max_nodes:
                lines.append(
                    f'  "_truncated" [label="... {len(selected) - max_nodes} more nodes", fillcolor="#eeeeee"];'
                )
                break
            color = _NODE_COLORS.get(node.type, "#ffffff")
            if node.is_admin is Tri.TRUE:
                color = "#f8b4b4"
            elif node.sensitivity is Sensitivity.HIGH:
                color = "#f9d58b"
            label = _dot_escape(f"{node.type.value}\\n{node.label}")
            lines.append(f'  "{_dot_escape(node_id)}" [label="{label}", fillcolor="{color}"];')
        for edge in self.edges:
            if edge.type not in allowed_edges:
                continue
            if edge.source not in selected or edge.target not in selected:
                continue
            style = "solid" if edge.confidence is Confidence.HIGH else "dashed"
            lines.append(
                f'  "{_dot_escape(edge.source)}" -> "{_dot_escape(edge.target)}" '
                f'[label="{_dot_escape(edge.label)}", style={style}];'
            )
        lines.append("}")
        return "\n".join(lines)


_NODE_COLORS: dict[NodeType, str] = {
    NodeType.ACCOUNT: "#e0e0e0",
    NodeType.USER: "#cfe2ff",
    NodeType.GROUP: "#e2d9f3",
    NodeType.ROLE: "#d1e7dd",
    NodeType.MANAGED_POLICY: "#f8f9fa",
    NodeType.S3_BUCKET: "#fff3cd",
    NodeType.LAMBDA_FUNCTION: "#ffe5d0",
    NodeType.EC2_INSTANCE: "#fde2c8",
    NodeType.EXTERNAL_ACCOUNT: "#f5c2c7",
    NodeType.EXTERNAL_PRINCIPAL: "#f5c2c7",
    NodeType.ANONYMOUS: "#f1aeb5",
    NodeType.INTERNET: "#f1aeb5",
    NodeType.SERVICE: "#dee2e6",
}


def _dot_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
