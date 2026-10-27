"""Bounded attack-path discovery.

Paths start at a principal-like node, move along *identity transition edges*
(a principal assuming a role, or a function executing as its role) and end either
at an administrative principal or at a sensitive resource reached through a final
``can-access`` edge. Depth, per-pair and total path counts are
capped so that a large or adversarial snapshot cannot cause a combinatorial
explosion; truncation is reported, never hidden.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from attackpath.graph.model import (
    AttackGraph,
    Edge,
    EdgeType,
    Node,
    lowest_confidence,
    weakest_evidence,
)
from attackpath.models.finding import Confidence, EvidenceKind, PathStep
from attackpath.tri import Tri

_EVIDENCE_RANK = {
    EvidenceKind.OBSERVED: 0,
    EvidenceKind.INFERRED: 1,
    EvidenceKind.HYPOTHETICAL: 2,
    EvidenceKind.INDETERMINATE: 3,
}
_CONFIDENCE_RANK = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


def _path_rank(path: AttackPath) -> tuple[int, int, int, tuple[str, ...]]:
    """Shortest first, then strongest evidence, then highest confidence, then stable order."""
    return (
        path.length,
        _EVIDENCE_RANK[path.evidence_kind],
        _CONFIDENCE_RANK[path.confidence],
        path.key,
    )


@dataclass(frozen=True)
class AttackPath:
    nodes: tuple[str, ...]
    edges: tuple[Edge, ...]
    target_kind: str  # "admin" or "resource"

    @property
    def source(self) -> str:
        return self.nodes[0]

    @property
    def target(self) -> str:
        return self.nodes[-1]

    @property
    def length(self) -> int:
        return len(self.edges)

    @property
    def confidence(self) -> Confidence:
        return lowest_confidence(e.confidence for e in self.edges)

    @property
    def evidence_kind(self) -> EvidenceKind:
        kind = weakest_evidence(e.evidence_kind for e in self.edges)
        # Reaching a target through several inferred hops is itself an inference.
        if kind is EvidenceKind.OBSERVED and self.length > 1:
            return EvidenceKind.INFERRED
        return kind

    @property
    def preconditions(self) -> tuple[str, ...]:
        seen: list[str] = []
        for edge in self.edges:
            for item in edge.preconditions:
                if item not in seen:
                    seen.append(item)
        return tuple(seen)

    @property
    def key(self) -> tuple[str, ...]:
        return tuple(f"{e.source}|{e.type.value}|{e.target}" for e in self.edges)

    def steps(self) -> list[PathStep]:
        return [
            PathStep(
                source=e.source,
                edge=e.type.value,
                target=e.target,
                description=e.label,
                confidence=e.confidence,
                evidence=e.evidence,
                preconditions=e.preconditions,
            )
            for e in self.edges
        ]

    def describe(self, graph: AttackGraph) -> str:
        parts = [_label(graph, self.nodes[0])]
        for edge in self.edges:
            parts.append(f"--[{edge.label}]--> {_label(graph, edge.target)}")
        return " ".join(parts)


def _label(graph: AttackGraph, node_id: str) -> str:
    node = graph.node(node_id)
    return f"{node.type.value}:{node.label}" if node else node_id


@dataclass
class PathSearchResult:
    paths: list[AttackPath]
    truncated: bool = False
    sources_searched: int = 0

    def by_source(self, source: str) -> list[AttackPath]:
        return [p for p in self.paths if p.source == source]

    def by_pair(self) -> dict[tuple[str, str], list[AttackPath]]:
        groups: dict[tuple[str, str], list[AttackPath]] = {}
        for path in self.paths:
            groups.setdefault((path.source, path.target), []).append(path)
        return groups


def default_target_classifier(graph: AttackGraph) -> Callable[[Node, Edge], str | None]:
    """Classify the node reached via ``edge`` as a target kind, or ``None``."""

    def classify(node: Node, edge: Edge) -> str | None:
        if edge.type is EdgeType.CAN_ACCESS:
            return "resource" if node.attrs.get("sensitive") else None
        if node.is_admin is Tri.TRUE:
            return "admin"
        return None

    return classify


def find_attack_paths(
    graph: AttackGraph,
    sources: Iterable[str],
    *,
    max_depth: int = 4,
    max_paths_per_pair: int = 5,
    max_total_paths: int = 10_000,
    classify: Callable[[Node, Edge], str | None] | None = None,
) -> PathSearchResult:
    """Enumerate simple paths from ``sources`` to admin nodes or sensitive resources."""
    classify = classify or default_target_classifier(graph)
    found: dict[tuple[str, str], list[AttackPath]] = {}
    seen_keys: set[tuple[str, ...]] = set()
    truncated = False
    total = 0
    searched = 0

    for source in sources:
        source_node = graph.node(source)
        if source_node is None or source_node.is_admin is Tri.TRUE:
            continue
        searched += 1
        stack: list[tuple[str, tuple[str, ...], tuple[Edge, ...]]] = [(source, (source,), ())]
        while stack:
            current, visited, edges = stack.pop()
            if len(edges) >= max_depth:
                continue
            for edge in graph.out_edges(current):
                if not edge.traversable or edge.target in visited:
                    continue
                target_node = graph.node(edge.target)
                if target_node is None:
                    continue
                new_edges = (*edges, edge)
                kind = classify(target_node, edge)
                if kind is not None:
                    path = AttackPath((*visited, edge.target), new_edges, kind)
                    if path.key in seen_keys:
                        continue
                    pair = (source, edge.target)
                    bucket = found.setdefault(pair, [])
                    if len(bucket) >= max_paths_per_pair:
                        truncated = True
                        continue
                    if total >= max_total_paths:
                        truncated = True
                        continue
                    seen_keys.add(path.key)
                    bucket.append(path)
                    total += 1
                    # An admin node is a terminal target; a resource cannot be extended.
                    continue
                if edge.type is EdgeType.CAN_ACCESS:
                    continue
                if not edge.is_transition:
                    continue
                stack.append((edge.target, (*visited, edge.target), new_edges))

    paths: list[AttackPath] = []
    for pair in sorted(found):
        paths.extend(sorted(found[pair], key=_path_rank))
    return PathSearchResult(paths=paths, truncated=truncated, sources_searched=searched)
