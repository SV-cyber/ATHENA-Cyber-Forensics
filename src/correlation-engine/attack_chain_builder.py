"""
ATHENA Correlation Engine - Attack Chain Builder

Goal:
Correlate multiple normalized events (from EventNormalizer) and ML predictions
to reconstruct attack chains and represent them as an attack graph.

Key ideas:
    - Events are linked by temporal proximity, shared source IP, and technique ordering.
    - A correlation strength score is computed per edge.
    - Chains are derived as weakly-connected components (or sequences) in the graph.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    import networkx as nx  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    nx = None  # type: ignore[assignment]


class _MiniDiGraph:
    """
    Minimal directed graph fallback when `networkx` is unavailable.
    Supports only what AttackChainBuilder uses.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def add_node(self, node: str, **attrs: Any) -> None:
        self._nodes.setdefault(node, {}).update(attrs)

    def add_edge(self, u: str, v: str, **attrs: Any) -> None:
        self._edges[(u, v)] = dict(attrs)

    @property
    def nodes(self) -> Any:
        class _NodesView:
            def __init__(self, parent: _MiniDiGraph) -> None:
                self._p = parent

            def get(self, n: str) -> Optional[Dict[str, Any]]:
                return self._p._nodes.get(n)

            def __iter__(self):
                return iter(self._p._nodes.items())

        return _NodesView(self)

    def nodes_data(self) -> List[Tuple[str, Dict[str, Any]]]:
        return list(self._nodes.items())

    def edges_data(self) -> List[Tuple[str, str, Dict[str, Any]]]:
        return [(u, v, d) for (u, v), d in self._edges.items()]

    def number_of_nodes(self) -> int:
        return len(self._nodes)

    def number_of_edges(self) -> int:
        return len(self._edges)

    def subgraph(self, node_ids: Iterable[str]) -> _MiniDiGraph:
        keep = set(node_ids)
        sg = _MiniDiGraph()
        for n in keep:
            if n in self._nodes:
                sg.add_node(n, **self._nodes[n])
        for (u, v), d in self._edges.items():
            if u in keep and v in keep:
                sg.add_edge(u, v, **d)
        return sg

    def copy(self) -> _MiniDiGraph:
        g = _MiniDiGraph()
        g._nodes = {k: dict(v) for k, v in self._nodes.items()}
        g._edges = {k: dict(v) for k, v in self._edges.items()}
        return g


def _weakly_connected_components_fallback(g: _MiniDiGraph) -> List[set]:
    # Undirected adjacency for weak connectivity.
    adj: Dict[str, set] = {n: set() for n, _ in g.nodes_data()}
    for u, v, _ in g.edges_data():
        adj.setdefault(u, set()).add(v)
        adj.setdefault(v, set()).add(u)

    seen: set = set()
    comps: List[set] = []
    for n in adj:
        if n in seen:
            continue
        stack = [n]
        comp = set()
        while stack:
            x = stack.pop()
            if x in seen:
                continue
            seen.add(x)
            comp.add(x)
            for y in adj.get(x, set()):
                if y not in seen:
                    stack.append(y)
        comps.append(comp)
    return comps


def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("athena.correlation.attack_chain_builder")
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


@dataclass(frozen=True)
class CorrelationConfig:
    # Time window for linking events from same source IP.
    max_time_gap_seconds: int = 15 * 60  # 15 minutes

    # Edge scoring weights
    w_time: float = 0.40
    w_same_src: float = 0.25
    w_technique_seq: float = 0.20
    w_model: float = 0.15

    # Minimum edge strength to keep.
    min_edge_strength: float = 0.45

    # Multi-stage threshold
    min_distinct_tactics_for_multistage: int = 4
    min_chain_length_for_multistage: int = 6


class AttackChainBuilder:
    """
    Correlate events + predictions into attack chains.

    Input:
        - events: list of normalized events dicts (EventNormalizer output)
        - predictions: optional list of per-event model outputs aligned by index,
          or dict keyed by event_id.

    Output:
        - attack_chains: list of chains (each chain is a dict with events + score)
        - attack_graph: networkx.DiGraph
    """

    def __init__(self, *, config: Optional[CorrelationConfig] = None) -> None:
        self.logger = _setup_logger()
        self.config = config or CorrelationConfig()

        self._events: List[Dict[str, Any]] = []
        self._pred_by_event_id: Dict[str, Dict[str, Any]] = {}
        if nx is None:
            self.logger.warning("networkx not installed; using minimal in-memory graph fallback.")
            self._graph = _MiniDiGraph()
        else:
            self._graph = nx.DiGraph()

    # -------------------------
    # Public API
    # -------------------------

    def correlate_events(
        self,
        events: Sequence[Dict[str, Any]],
        predictions: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Create correlations and return both chains and graph structure.

        Args:
            events: normalized events (must include event_id, timestamp, source_ip, tactic, technique_id)
            predictions:
                - None
                - list of dicts aligned with `events` (e.g. output of ThreatDetectionModel.predict(df).to_dict('records'))
                - dict keyed by event_id -> prediction dict

        Returns:
            { "attack_chains": [...], "graph": <serialized graph> }
        """
        self._events = [dict(e) for e in events]
        self._pred_by_event_id = self._index_predictions(events=self._events, predictions=predictions)

        self._graph = self.build_attack_graph()
        chains = self._extract_attack_chains()

        return {
            "attack_chains": chains,
            "graph": self._serialize_graph(self._graph),
        }

    def build_attack_graph(self) -> nx.DiGraph:
        """
        Build a directed graph:
            - nodes: events
            - edges: correlations (strength + reasons)
        """
        if nx is None:
            g = _MiniDiGraph()
        else:
            g = nx.DiGraph()

        # Sort by timestamp for efficient temporal linking.
        events_sorted = sorted(self._events, key=lambda e: self._parse_ts(e.get("timestamp")))

        # Add nodes
        for ev in events_sorted:
            eid = str(ev.get("event_id") or "")
            if not eid:
                continue
            pred = self._pred_by_event_id.get(eid, {})
            g.add_node(eid, **{"event": ev, "prediction": pred})

        # Create edges using a sliding window in time.
        n = len(events_sorted)
        for i in range(n):
            a = events_sorted[i]
            a_id = str(a.get("event_id") or "")
            if not a_id:
                continue

            a_ts = self._parse_ts(a.get("timestamp"))
            for j in range(i + 1, n):
                b = events_sorted[j]
                b_id = str(b.get("event_id") or "")
                if not b_id:
                    continue

                b_ts = self._parse_ts(b.get("timestamp"))
                gap = (b_ts - a_ts).total_seconds()
                if gap < 0:
                    continue
                if gap > self.config.max_time_gap_seconds:
                    # Because sorted, we can break early.
                    break

                strength, reasons = self._score_edge(a, b, gap_seconds=gap)
                if strength >= self.config.min_edge_strength:
                    g.add_edge(a_id, b_id, strength=float(strength), reasons=reasons, gap_seconds=float(gap))

        self.logger.info("Attack graph built: nodes=%d edges=%d", g.number_of_nodes(), g.number_of_edges())
        return g

    def get_attack_timeline(self, chain_event_ids: Sequence[str]) -> List[Dict[str, Any]]:
        """
        Return events in chronological order for a given chain.
        """
        events = []
        for eid in chain_event_ids:
            node = self._graph.nodes.get(eid) if self._graph is not None else None
            if node and "event" in node:
                events.append(node["event"])
        return sorted(events, key=lambda e: self._parse_ts(e.get("timestamp")))

    def detect_multi_stage_attack(self, chain_event_ids: Sequence[str]) -> Dict[str, Any]:
        """
        Detect whether a chain resembles a multi-stage attack.
        """
        timeline = self.get_attack_timeline(chain_event_ids)
        tactics = [str(e.get("tactic") or "") for e in timeline]
        distinct_tactics = {t for t in tactics if t}

        is_multistage = (
            len(timeline) >= self.config.min_chain_length_for_multistage
            and len(distinct_tactics) >= self.config.min_distinct_tactics_for_multistage
        )

        return {
            "is_multi_stage": bool(is_multistage),
            "event_count": int(len(timeline)),
            "distinct_tactics": sorted(distinct_tactics),
        }

    # -------------------------
    # Scoring + extraction
    # -------------------------

    def _score_edge(self, a: Dict[str, Any], b: Dict[str, Any], *, gap_seconds: float) -> Tuple[float, List[str]]:
        """
        Compute correlation strength between two events.
        """
        reasons: List[str] = []

        # 1) Time proximity: closer events score higher.
        time_score = max(0.0, 1.0 - (gap_seconds / float(self.config.max_time_gap_seconds)))
        if time_score > 0.0:
            reasons.append("timestamp_proximity")

        # 2) Same source IP
        same_src = str(a.get("source_ip") or "") and (a.get("source_ip") == b.get("source_ip"))
        same_src_score = 1.0 if same_src else 0.0
        if same_src:
            reasons.append("same_source_ip")

        # 3) Technique sequence: if techniques differ and tactics are not identical,
        # favor forward progress in lifecycle.
        seq_score = self._technique_sequence_score(a, b)
        if seq_score > 0.0:
            reasons.append("technique_sequence")

        # 4) Model signal: if both events look malicious/anomalous, strengthen edge.
        model_score = self._model_pair_score(a, b)
        if model_score > 0.0:
            reasons.append("model_signal")

        strength = (
            self.config.w_time * time_score
            + self.config.w_same_src * same_src_score
            + self.config.w_technique_seq * seq_score
            + self.config.w_model * model_score
        )

        return float(round(strength, 4)), reasons

    def _technique_sequence_score(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:
        """
        Score whether `b` plausibly follows `a` in an attack chain.
        """
        a_tactic = str(a.get("tactic") or "")
        b_tactic = str(b.get("tactic") or "")

        if not a_tactic or not b_tactic:
            return 0.0

        # Same technique_id repeating is often redundant; reduce score.
        if str(a.get("technique_id") or "") == str(b.get("technique_id") or ""):
            return 0.15

        # Use lifecycle ordering if present (EventNormalizer tactic ordering).
        order = [
            "Reconnaissance",
            "Initial Access",
            "Execution",
            "Persistence",
            "Privilege Escalation",
            "Defense Evasion",
            "Credential Access",
            "Discovery",
            "Lateral Movement",
            "Collection",
            "Exfiltration",
            "Command and Control",
        ]
        idx = {t: i for i, t in enumerate(order)}
        if a_tactic in idx and b_tactic in idx:
            if idx[b_tactic] >= idx[a_tactic]:
                # Forward progress -> higher.
                delta = idx[b_tactic] - idx[a_tactic]
                return 1.0 if delta <= 2 else max(0.3, 1.0 - (0.1 * delta))
            # Backward jumps are possible but less likely.
            return 0.2

        # Unknown tactics
        return 0.25 if a_tactic != b_tactic else 0.1

    def _model_pair_score(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:
        """
        Use ML predictions to strengthen/attenuate correlations.

        Accepted prediction formats:
            - per-event dict may include:
                - is_malicious_pred (0/1)
                - p_malicious_lstm (0-1)
                - anomaly_score_iforest (float; higher => more anomalous)
        """
        a_id = str(a.get("event_id") or "")
        b_id = str(b.get("event_id") or "")
        pa = self._pred_by_event_id.get(a_id, {})
        pb = self._pred_by_event_id.get(b_id, {})

        def score_one(p: Dict[str, Any]) -> float:
            if not isinstance(p, dict):
                return 0.0
            p_mal = p.get("p_malicious_lstm")
            pred = p.get("is_malicious_pred")
            if isinstance(p_mal, (int, float)):
                return float(max(0.0, min(1.0, p_mal)))
            if isinstance(pred, (int, float)):
                return 1.0 if int(pred) == 1 else 0.0
            return 0.0

        sa = score_one(pa)
        sb = score_one(pb)
        return float((sa + sb) / 2.0)

    def _extract_attack_chains(self) -> List[Dict[str, Any]]:
        """
        Extract chains from the graph as weakly connected components.
        For each component, produce a timeline-ordered chain and a chain score.
        """
        g = self._graph
        if g.number_of_nodes() == 0:
            return []

        chains: List[Dict[str, Any]] = []

        if nx is None:
            components = _weakly_connected_components_fallback(g)  # type: ignore[arg-type]
        else:
            components = nx.weakly_connected_components(g)  # type: ignore[assignment]

        for comp in components:
            node_ids = list(comp)
            timeline_events = self.get_attack_timeline(node_ids)
            timeline_ids = [str(e.get("event_id")) for e in timeline_events if e.get("event_id")]

            # Chain score: average of edge strengths within the induced subgraph.
            sub = g.subgraph(node_ids).copy()
            if nx is None:
                strengths = [float(d.get("strength", 0.0)) for _, _, d in sub.edges_data()]  # type: ignore[attr-defined]
            else:
                strengths = [float(d.get("strength", 0.0)) for _, _, d in sub.edges(data=True)]
            chain_score = float(sum(strengths) / len(strengths)) if strengths else 0.0

            ms = self.detect_multi_stage_attack(timeline_ids)

            chains.append(
                {
                    "chain_id": f"chain-{min(timeline_ids) if timeline_ids else len(chains)}",
                    "event_ids": timeline_ids,
                    "event_count": int(len(timeline_ids)),
                    "chain_score": round(chain_score, 4),
                    "multi_stage": ms,
                }
            )

        # Higher score first, longer chains next.
        chains.sort(key=lambda c: (c.get("chain_score", 0.0), c.get("event_count", 0)), reverse=True)
        self.logger.info("Extracted attack chains: count=%d", len(chains))
        return chains

    # -------------------------
    # Predictions + serialization
    # -------------------------

    def _index_predictions(self, *, events: Sequence[Dict[str, Any]], predictions: Optional[Any]) -> Dict[str, Dict[str, Any]]:
        if predictions is None:
            return {}

        # Case 1: dict keyed by event_id
        if isinstance(predictions, dict):
            out: Dict[str, Dict[str, Any]] = {}
            for k, v in predictions.items():
                if k is None:
                    continue
                if isinstance(v, dict):
                    out[str(k)] = dict(v)
            return out

        # Case 2: list aligned with events
        if isinstance(predictions, list):
            out = {}
            for ev, pred in zip(events, predictions):
                eid = str(ev.get("event_id") or "")
                if not eid:
                    continue
                if isinstance(pred, dict):
                    out[eid] = dict(pred)
            return out

        return {}

    def _serialize_graph(self, g: nx.DiGraph) -> Dict[str, Any]:
        """
        Serialize graph to a JSON-friendly structure.
        """
        nodes = []
        if nx is None:
            node_iter = g.nodes_data()  # type: ignore[attr-defined]
        else:
            node_iter = g.nodes(data=True)

        for nid, data in node_iter:
            event = (data.get("event") or {}) if isinstance(data.get("event"), dict) else {}
            pred = (data.get("prediction") or {}) if isinstance(data.get("prediction"), dict) else {}
            nodes.append({"id": nid, "event": event, "prediction": pred})

        edges = []
        if nx is None:
            edge_iter = g.edges_data()  # type: ignore[attr-defined]
        else:
            edge_iter = g.edges(data=True)

        for u, v, data in edge_iter:
            edges.append(
                {
                    "source": u,
                    "target": v,
                    "strength": float(data.get("strength", 0.0)),
                    "gap_seconds": float(data.get("gap_seconds", 0.0)),
                    "reasons": list(data.get("reasons", [])),
                }
            )

        return {"nodes": nodes, "edges": edges}

    # -------------------------
    # Timestamp parsing
    # -------------------------

    def _parse_ts(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        if isinstance(value, str) and value.strip():
            try:
                dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                pass
        return datetime.now(timezone.utc)


if __name__ == "__main__":
    # Minimal usage example (mock events + predictions).
    events = [
        {
            "event_id": "e1",
            "timestamp": "2026-03-17T00:00:00+00:00",
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.20",
            "event_type": "Discovery:T1016",
            "tactic": "Discovery",
            "technique_id": "T1016",
            "severity": "medium",
            "is_malicious": True,
        },
        {
            "event_id": "e2",
            "timestamp": "2026-03-17T00:03:00+00:00",
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.30",
            "event_type": "Lateral Movement:T1021.006",
            "tactic": "Lateral Movement",
            "technique_id": "T1021.006",
            "severity": "high",
            "is_malicious": True,
        },
    ]

    predictions = [
        {"p_malicious_lstm": 0.62, "anomaly_score_iforest": 0.5, "is_malicious_pred": 1},
        {"p_malicious_lstm": 0.81, "anomaly_score_iforest": 0.9, "is_malicious_pred": 1},
    ]

    builder = AttackChainBuilder()
    result = builder.correlate_events(events, predictions=predictions)
    print("Chains:", result["attack_chains"])
    print("Graph edges:", result["graph"]["edges"])

