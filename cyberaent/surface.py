"""Attack-surface graph: endpoints, parameters, technologies, auth and roles.

Nodes and edges live inside the persistent memory document, so the graph is
rebuilt (and re-readable) across sessions. Edges are directional and typed
(``uses``, ``exposes``, ``parameter_of``, ``authenticates``, ``authorized_by``,
``part_of``) which lets the agent reason about *relationships* instead of a flat
list of URLs.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from .memory import SessionMemory, canonical_url

NODE_TYPES: tuple[str, ...] = (
    "endpoint",
    "technology",
    "parameter",
    "auth",
    "role",
    "resource",
)

EDGE_TYPES: tuple[str, ...] = (
    "exposes",
    "uses",
    "parameter_of",
    "authenticates",
    "authorized_by",
    "part_of",
)

MAX_NODES = 2000
MAX_EDGES = 4000


def node_id(kind: str, label: str) -> str:
    return f"{kind}:{str(label).strip().lower()}"


class AttackSurface:
    """Typed graph over the facts stored in :class:`SessionMemory`."""

    def __init__(self, memory: SessionMemory):
        self._memory = memory
        graph = memory.state.setdefault("graph", {"nodes": {}, "edges": {}})
        self._nodes: dict[str, dict[str, Any]] = graph.setdefault("nodes", {})
        self._edges: dict[str, dict[str, Any]] = graph.setdefault("edges", {})

    # ------------------------------------------------------------------ nodes
    def upsert(self, kind: str, label: str, **attrs: Any) -> str | None:
        if kind not in NODE_TYPES:
            return None
        clean = str(label or "").strip()
        if not clean:
            return None
        nid = node_id(kind, clean)
        node = self._nodes.get(nid)
        if node is None:
            node = {"id": nid, "kind": kind, "label": clean, "first_seen": attrs.pop("seen", None)}
            self._nodes[nid] = node
            self._prune()
        for key, value in attrs.items():
            if value in (None, "", [], {}):
                continue
            current = node.get(key)
            if isinstance(current, list):
                if value not in current:
                    current.append(value)
            elif key not in node or not node[key]:
                node[key] = value
        return nid

    def _prune(self) -> None:
        if len(self._nodes) <= MAX_NODES:
            return
        excess = len(self._nodes) - MAX_NODES
        for key in list(self._nodes)[:excess]:
            self._nodes.pop(key, None)
            self._edges = {
                k: v for k, v in self._edges.items() if v.get("from") != key and v.get("to") != key
            }

    # ------------------------------------------------------------------ edges
    def link(self, source: str, relation: str, target: str) -> dict[str, Any] | None:
        if source not in self._nodes or target not in self._nodes:
            return None
        if relation not in EDGE_TYPES:
            return None
        key = f"{source}|{relation}|{target}"
        edge = self._edges.get(key)
        if edge is None:
            edge = {"from": source, "rel": relation, "to": target}
            self._edges[key] = edge
            self._prune_edges()
        return edge

    def _prune_edges(self) -> None:
        if len(self._edges) > MAX_EDGES:
            excess = len(self._edges) - MAX_EDGES
            for key in list(self._edges)[:excess]:
                self._edges.pop(key, None)

    # -------------------------------------------------------------- ingestion
    def remember_endpoint(
        self,
        *,
        url: str,
        method: str = "GET",
        params: Iterable[str] = (),
        tech: str = "",
        auth: str = "",
        role: str = "",
        status: Any = None,
        source: str = "",
    ) -> str | None:
        canonical, url_params = canonical_url(url)
        if not canonical:
            return None
        verb = str(method or "GET").strip().upper()[:12]
        endpoint = self.upsert("endpoint", f"{verb} {canonical}", method=verb, status=status,
                              source=source or None)
        if endpoint is None:
            return None
        self.upsert("resource", canonical)
        host = canonical.split("://", 1)[-1].split("/", 1)[0]
        self.upsert("resource", host)
        if tech:
            tech_node = self.upsert("technology", tech)
            if tech_node:
                self.link(tech_node, "uses", endpoint)
        if auth:
            auth_node = self.upsert("auth", auth)
            if auth_node:
                self.link(auth_node, "authenticates", endpoint)
        if role:
            role_node = self.upsert("role", role)
            if role_node:
                self.link(endpoint, "authorized_by", role_node)
        names = {str(p).strip() for p in (*url_params, *params) if str(p).strip()}
        for name in sorted(names):
            param_node = self.upsert("parameter", name)
            if param_node:
                self.link(param_node, "parameter_of", endpoint)
        self._memory.remember_endpoint(
            url=canonical,
            method=verb,
            params=sorted(names),
            status=status,
            tech=tech,
            auth=auth,
            role=role,
            source=source,
        )
        if tech:
            self._memory.remember_technology(name=tech, source=source)
        return endpoint

    # ---------------------------------------------------------------- queries
    def nodes(self, *, kind: str = "") -> list[dict[str, Any]]:
        rows = [dict(node) for node in self._nodes.values()]
        if kind:
            rows = [node for node in rows if node.get("kind") == kind]
        return sorted(rows, key=lambda node: str(node.get("id")))

    def edges(self, *, relation: str = "") -> list[dict[str, Any]]:
        rows = [dict(edge) for edge in self._edges.values()]
        if relation:
            rows = [edge for edge in rows if edge.get("rel") == relation]
        return sorted(rows, key=lambda edge: (str(edge.get("from")), str(edge.get("rel"))))

    def neighbors(self, target: str, *, kind: str = "") -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for edge in self._edges.values():
            other = None
            relation = ""
            if edge.get("from") == target:
                other, relation = str(edge.get("to")), "out"
            elif edge.get("to") == target:
                other, relation = str(edge.get("from")), "in"
            if other is None or other not in self._nodes:
                continue
            if kind and self._nodes[other].get("kind") != kind:
                continue
            node = dict(self._nodes[other])
            node["direction"] = relation
            node["relation"] = edge.get("rel")
            seen[other] = node
        return [seen[key] for key in sorted(seen)]

    def endpoints(self) -> list[dict[str, Any]]:
        return self.nodes(kind="endpoint")

    def parameters(self) -> list[str]:
        return [str(node["label"]) for node in self.nodes(kind="parameter")]

    def technologies(self) -> list[str]:
        return [str(node["label"]) for node in self.nodes(kind="technology")]

    def hosts(self) -> list[str]:
        hosts: set[str] = set()
        for node in self.nodes(kind="endpoint"):
            label = str(node.get("label", ""))
            target = label.split(" ", 1)[1] if " " in label else label
            host = urlsplit(target).netloc or target
            if host:
                hosts.add(host)
        return sorted(hosts)

    def save(self) -> None:
        self._memory.save()

    def stats(self) -> dict[str, int]:
        by_kind: dict[str, int] = {}
        for node in self._nodes.values():
            kind = str(node.get("kind"))
            by_kind[kind] = by_kind.get(kind, 0) + 1
        result = {"nodes": len(self._nodes), "edges": len(self._edges)}
        result.update(by_kind)
        return result

    # ----------------------------------------------------------------- render
    def markdown(self, *, limit: int = 25) -> str:
        stats = self.stats()
        lines = [
            "# Attack surface",
            "",
            f"Nodes: {stats.get('nodes', 0)} · Edges: {stats.get('edges', 0)}",
            "",
        ]
        endpoints = self.endpoints()
        if endpoints:
            header = "| Endpoint | Status | Tech | Auth | Role |"
            lines += ["## Endpoints", "", header, "| --- | --- | --- | --- | --- |"]
            for node in endpoints[:limit]:
                raw_tech = node.get("technologies")
                techs = raw_tech if isinstance(raw_tech, list) else []
                lines.append(
                    f"| {node.get('label')} | {node.get('status') or '-'} "
                    f"| {', '.join(str(t) for t in techs) or '-'} "
                    f"| {node.get('auth') or '-'} | {node.get('role') or '-'} |"
                )
            lines.append("")
        params = self.parameters()
        if params:
            lines += ["## Parameters", "", ", ".join(f"`{p}`" for p in params[:limit]), ""]
        techs = self.technologies()
        if techs:
            lines += ["## Technologies", "", ", ".join(f"`{t}`" for t in techs[:limit]), ""]
        roles = self.nodes(kind="role")
        if roles:
            lines += ["## Roles", "", ", ".join(f"`{r.get('label')}`" for r in roles[:limit]), ""]
        auths = self.nodes(kind="auth")
        if auths:
            labels = ", ".join(f"`{a.get('label')}`" for a in auths[:limit])
            lines += ["## Auth schemes", "", labels, ""]
        if len(lines) <= 4:
            lines += ["_No surface data captured yet._", ""]
        return "\n".join(lines)

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()
