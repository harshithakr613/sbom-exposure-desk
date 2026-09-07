"""
Dependency graph construction and traversal  (Capstone 1, Objective 2 / Phase 3)

Two graphs, answering two different questions.

1. REVERSE COMPONENT GRAPH — component -> repositories that contain it.
   Answers "a CVE just landed on lodash; which of our repositories are exposed?"
   This is the organisation-wide traversal Capstone 1 specified, and it works
   from a flat component inventory, which is what GitHub's dependency-graph SBOM
   provides.

2. DEPENDENCY CHAIN GRAPH — package -> package, built from SPDX relationships.
   Answers "how did lodash get in here?" and yields the path
   app -> webpack -> lodash. GitHub populates SPDX relationships inconsistently,
   so chains are reconstructed only where the data supports it and the absence
   is reported rather than guessed at.

NetworkX is used when installed; an equivalent pure-standard-library
implementation runs otherwise, so the module is never an installation problem.
"""

from collections import defaultdict, deque

try:  # pragma: no cover - environment dependent
    import networkx as nx
    BACKEND = "networkx"
except Exception:  # pragma: no cover
    nx = None
    BACKEND = "builtin"


def component_key(component):
    """Identity used for graph nodes: ecosystem + name, version-independent."""
    return "%s|%s" % (
        (component.get("ecosystem") or "").lower(),
        (component.get("name") or "").lower(),
    )


class ReverseDependencyGraph:
    """
    Maps each component to every repository containing it.

    Built once per sync and queried per advisory, which is the right way round:
    advisories arrive continuously, the inventory changes rarely.
    """

    def __init__(self):
        self._component_to_repos = defaultdict(set)
        self._repo_components = defaultdict(list)
        self._versions = defaultdict(set)

    def add(self, repository, component):
        key = component_key(component)
        self._component_to_repos[key].add(repository)
        self._repo_components[repository].append(component)
        if component.get("version"):
            self._versions[key].add(str(component["version"]))

    @classmethod
    def build(cls, repo_components):
        """repo_components: {repository_name: [component, ...]}"""
        graph = cls()
        for repository, components in repo_components.items():
            for component in components:
                graph.add(repository, component)
        return graph

    def repositories_containing(self, ecosystem, name):
        return sorted(self._component_to_repos.get(
            "%s|%s" % ((ecosystem or "").lower(), (name or "").lower()), set()))

    def versions_of(self, ecosystem, name):
        return sorted(self._versions.get(
            "%s|%s" % ((ecosystem or "").lower(), (name or "").lower()), set()))

    def blast_radius(self, ecosystem, name):
        """
        What a single advisory touches across the organisation.

        The number that turns a chore into leverage: one upgrade, N repositories.
        """
        repos = self.repositories_containing(ecosystem, name)
        return {
            "component": name,
            "ecosystem": ecosystem,
            "repository_count": len(repos),
            "repositories": repos,
            "versions_present": self.versions_of(ecosystem, name),
        }

    def shared_components(self, minimum=2):
        """Components appearing in several repositories, most widespread first."""
        shared = [
            {"key": key, "repository_count": len(repos),
             "repositories": sorted(repos)}
            for key, repos in self._component_to_repos.items()
            if len(repos) >= minimum
        ]
        shared.sort(key=lambda s: -s["repository_count"])
        return shared

    @property
    def component_count(self):
        return len(self._component_to_repos)

    @property
    def repository_count(self):
        return len(self._repo_components)


class DependencyChainGraph:
    """
    Package-to-package edges, reconstructed from SPDX relationships.

    SPDX expresses "A DEPENDS_ON B" between SPDX element ids. Where GitHub
    populates those relationships the true chain can be walked; where it does
    not, `chain_to` returns None and the caller reports transitive detection
    without a rendered path rather than inventing one.
    """

    DEPENDENCY_TYPES = {"DEPENDS_ON", "CONTAINS", "DYNAMIC_LINK", "STATIC_LINK"}

    def __init__(self):
        self._edges = defaultdict(set)
        self._names = {}
        self._roots = set()
        self._graph = nx.DiGraph() if nx is not None else None

    @classmethod
    def from_spdx(cls, sbom):
        """Build from a GitHub dependency-graph SPDX document."""
        graph = cls()
        packages = (sbom or {}).get("packages", []) or []
        for package in packages:
            spdx_id = package.get("SPDXID")
            if spdx_id:
                graph._names[spdx_id] = package.get("name") or spdx_id

        described = set((sbom or {}).get("documentDescribes", []) or [])
        graph._roots |= described

        for relationship in (sbom or {}).get("relationships", []) or []:
            kind = relationship.get("relationshipType")
            source = relationship.get("spdxElementId")
            target = relationship.get("relatedSpdxElement")
            if not source or not target:
                continue
            if kind == "DESCRIBES":
                graph._roots.add(target)
                continue
            if kind in cls.DEPENDENCY_TYPES:
                graph._edges[source].add(target)
                if graph._graph is not None:
                    graph._graph.add_edge(source, target)
        return graph

    @property
    def has_relationships(self):
        """False when the SBOM carries no usable dependency edges."""
        return bool(self._edges)

    @property
    def edge_count(self):
        return sum(len(targets) for targets in self._edges.values())

    def _name(self, spdx_id):
        return self._names.get(spdx_id, spdx_id)

    def chain_to(self, target_name):
        """
        Shortest path from a root package to the named component.

        Returns a list of readable names, or None when no path exists — which
        is the honest answer for a flat SBOM.
        """
        if not self._edges:
            return None

        targets = {sid for sid, name in self._names.items()
                   if name and name.lower() == str(target_name).lower()}
        if not targets:
            return None

        starts = self._roots or set(self._edges)

        if self._graph is not None:
            for start in starts:
                for target in targets:
                    if start in self._graph and target in self._graph:
                        try:
                            path = nx.shortest_path(self._graph, start, target)
                            return [self._name(n) for n in path]
                        except nx.NetworkXNoPath:
                            continue
            return None

        # Breadth-first search, equivalent to the NetworkX path above.
        for start in starts:
            queue = deque([(start, [start])])
            seen = {start}
            while queue:
                node, path = queue.popleft()
                if node in targets:
                    return [self._name(n) for n in path]
                for neighbour in self._edges.get(node, ()):
                    if neighbour not in seen:
                        seen.add(neighbour)
                        queue.append((neighbour, path + [neighbour]))
        return None

    def depth_of(self, target_name):
        """
        How deep in the tree a component sits. 1 means a direct dependency.
        None when the chain cannot be reconstructed.
        """
        chain = self.chain_to(target_name)
        return (len(chain) - 1) if chain else None

    def is_direct(self, target_name):
        depth = self.depth_of(target_name)
        return depth == 1 if depth is not None else None
