"""
地址关联图谱

Phase 2.4: 构建地址关系网络

功能：
- 交易关系图构建
- 一跳/多跳关联查询
- 路径分析
- 社区检测（地址聚类）
"""

from dataclasses import dataclass, field
from datetime import datetime as dt
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict
from enum import Enum


class EdgeType(str, Enum):
    """边类型"""
    ETH_TRANSFER = "eth_transfer"       # ETH转账
    TOKEN_TRANSFER = "token_transfer"   # 代币转账
    CONTRACT_CALL = "contract_call"     # 合约调用
    CONTRACT_CREATE = "contract_create" # 合约创建


@dataclass
class Edge:
    """图的边（交易关系）"""
    from_address: str
    to_address: str
    edge_type: EdgeType
    tx_count: int = 1                   # 交易次数
    total_value_eth: float = 0.0        # 总金额
    first_tx_time: Optional[dt] = None
    last_tx_time: Optional[dt] = None
    tx_hashes: List[str] = field(default_factory=list)

    def add_transaction(
        self,
        value_eth: float,
        tx_time: dt,
        tx_hash: str
    ):
        """添加一笔交易"""
        self.tx_count += 1
        self.total_value_eth += value_eth

        if self.first_tx_time is None or tx_time < self.first_tx_time:
            self.first_tx_time = tx_time
        if self.last_tx_time is None or tx_time > self.last_tx_time:
            self.last_tx_time = tx_time

        if len(self.tx_hashes) < 100:  # 限制存储的交易哈希数量
            self.tx_hashes.append(tx_hash)


@dataclass
class Node:
    """图的节点（地址）"""
    address: str
    in_degree: int = 0                  # 入度（收款次数）
    out_degree: int = 0                 # 出度（转账次数）
    in_volume: float = 0.0              # 入账金额
    out_volume: float = 0.0             # 出账金额
    labels: List[str] = field(default_factory=list)


class AddressGraph:
    """地址关联图"""

    def __init__(self):
        # 邻接表：出边
        self.out_edges: Dict[str, Dict[str, Edge]] = defaultdict(dict)
        # 邻接表：入边
        self.in_edges: Dict[str, Dict[str, Edge]] = defaultdict(dict)
        # 节点信息
        self.nodes: Dict[str, Node] = {}

    def add_edge(
        self,
        from_addr: str,
        to_addr: str,
        edge_type: EdgeType,
        value_eth: float = 0.0,
        tx_time: Optional[dt] = None,
        tx_hash: str = ""
    ):
        """添加边（交易关系）"""
        from_lower = from_addr.lower()
        to_lower = to_addr.lower()

        # 确保节点存在
        self._ensure_node(from_lower)
        self._ensure_node(to_lower)

        # 检查边是否已存在
        if to_lower in self.out_edges[from_lower]:
            edge = self.out_edges[from_lower][to_lower]
            edge.add_transaction(value_eth, tx_time, tx_hash)
        else:
            edge = Edge(
                from_address=from_lower,
                to_address=to_lower,
                edge_type=edge_type,
                tx_count=1,
                total_value_eth=value_eth,
                first_tx_time=tx_time,
                last_tx_time=tx_time,
                tx_hashes=[tx_hash] if tx_hash else [],
            )
            self.out_edges[from_lower][to_lower] = edge
            self.in_edges[to_lower][from_lower] = edge

        # 更新节点统计
        self.nodes[from_lower].out_degree += 1
        self.nodes[from_lower].out_volume += value_eth
        self.nodes[to_lower].in_degree += 1
        self.nodes[to_lower].in_volume += value_eth

    def _ensure_node(self, address: str):
        """确保节点存在"""
        if address not in self.nodes:
            self.nodes[address] = Node(address=address)

    def get_neighbors(
        self,
        address: str,
        direction: str = "both"
    ) -> List[Tuple[str, Edge]]:
        """获取邻居节点

        Args:
            address: 目标地址
            direction: "out"(出边), "in"(入边), "both"(双向)

        Returns:
            [(邻居地址, 边信息), ...]
        """
        addr_lower = address.lower()
        neighbors = []

        if direction in ["out", "both"]:
            for to_addr, edge in self.out_edges.get(addr_lower, {}).items():
                neighbors.append((to_addr, edge))

        if direction in ["in", "both"]:
            for from_addr, edge in self.in_edges.get(addr_lower, {}).items():
                neighbors.append((from_addr, edge))

        return neighbors

    def get_n_hop_neighbors(
        self,
        address: str,
        n: int = 2,
        direction: str = "both",
        max_nodes: int = 1000
    ) -> Dict[int, Set[str]]:
        """获取N跳内的所有邻居

        Args:
            address: 起始地址
            n: 跳数
            direction: 方向
            max_nodes: 最大节点数限制

        Returns:
            {hop_distance: set(addresses)}
        """
        addr_lower = address.lower()
        result: Dict[int, Set[str]] = {0: {addr_lower}}
        visited = {addr_lower}
        current_level = {addr_lower}

        for hop in range(1, n + 1):
            next_level = set()

            for addr in current_level:
                for neighbor, _ in self.get_neighbors(addr, direction):
                    if neighbor not in visited:
                        next_level.add(neighbor)
                        visited.add(neighbor)

                        if len(visited) >= max_nodes:
                            result[hop] = next_level
                            return result

            if not next_level:
                break

            result[hop] = next_level
            current_level = next_level

        return result

    def find_path(
        self,
        from_addr: str,
        to_addr: str,
        max_depth: int = 5
    ) -> Optional[List[str]]:
        """查找两地址间的路径（BFS）

        Args:
            from_addr: 起始地址
            to_addr: 目标地址
            max_depth: 最大搜索深度

        Returns:
            路径列表 [from_addr, ..., to_addr] 或 None
        """
        from_lower = from_addr.lower()
        to_lower = to_addr.lower()

        if from_lower == to_lower:
            return [from_lower]

        # BFS
        queue = [(from_lower, [from_lower])]
        visited = {from_lower}

        while queue:
            current, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            for neighbor, _ in self.get_neighbors(current, "out"):
                if neighbor == to_lower:
                    return path + [neighbor]

                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def get_subgraph(
        self,
        center_addr: str,
        hops: int = 1
    ) -> 'AddressGraph':
        """提取以某地址为中心的子图"""
        subgraph = AddressGraph()
        hop_neighbors = self.get_n_hop_neighbors(center_addr, hops)

        # 收集所有相关地址
        all_addrs = set()
        for addrs in hop_neighbors.values():
            all_addrs.update(addrs)

        # 复制相关边
        for addr in all_addrs:
            for neighbor, edge in self.get_neighbors(addr, "out"):
                if neighbor in all_addrs:
                    subgraph.add_edge(
                        edge.from_address,
                        edge.to_address,
                        edge.edge_type,
                        edge.total_value_eth,
                        edge.last_tx_time,
                    )

        return subgraph

    def get_statistics(self) -> Dict[str, Any]:
        """获取图的统计信息"""
        if not self.nodes:
            return {"nodes": 0, "edges": 0}

        total_edges = sum(len(edges) for edges in self.out_edges.values())
        degrees = [n.in_degree + n.out_degree for n in self.nodes.values()]
        volumes = [n.in_volume + n.out_volume for n in self.nodes.values()]

        return {
            "nodes": len(self.nodes),
            "edges": total_edges,
            "avg_degree": sum(degrees) / len(degrees) if degrees else 0,
            "max_degree": max(degrees) if degrees else 0,
            "total_volume_eth": sum(volumes) / 2,  # 除2避免重复计算
        }

    def find_high_centrality_nodes(self, top_n: int = 10) -> List[Tuple[str, float]]:
        """找出中心度最高的节点（简化版，使用度数作为代理）"""
        scores = []
        for addr, node in self.nodes.items():
            # 简单中心度 = 入度 + 出度
            centrality = node.in_degree + node.out_degree
            scores.append((addr, centrality))

        scores.sort(key=lambda x: -x[1])
        return scores[:top_n]

    def detect_clusters(self, min_cluster_size: int = 3) -> List[Set[str]]:
        """检测地址簇（简化版连通分量）"""
        visited = set()
        clusters = []

        for addr in self.nodes:
            if addr in visited:
                continue

            # BFS找连通分量
            cluster = set()
            queue = [addr]

            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue

                visited.add(current)
                cluster.add(current)

                for neighbor, _ in self.get_neighbors(current, "both"):
                    if neighbor not in visited:
                        queue.append(neighbor)

            if len(cluster) >= min_cluster_size:
                clusters.append(cluster)

        return clusters

    def export_for_visualization(self) -> Dict[str, Any]:
        """导出为可视化格式"""
        nodes = []
        for addr, node in self.nodes.items():
            nodes.append({
                "id": addr,
                "in_degree": node.in_degree,
                "out_degree": node.out_degree,
                "volume": node.in_volume + node.out_volume,
                "labels": node.labels,
            })

        edges = []
        for from_addr, to_edges in self.out_edges.items():
            for to_addr, edge in to_edges.items():
                edges.append({
                    "source": from_addr,
                    "target": to_addr,
                    "type": edge.edge_type.value,
                    "tx_count": edge.tx_count,
                    "value": edge.total_value_eth,
                })

        return {
            "nodes": nodes,
            "edges": edges,
            "stats": self.get_statistics(),
        }


class GraphBuilder:
    """从交易数据构建图"""

    def __init__(self):
        self.graph = AddressGraph()

    def add_transaction(self, tx: 'Transaction'):
        """从交易添加边"""
        from src.models.ethereum import TransactionType

        if not tx.to_address:
            return  # 跳过合约创建

        edge_type = EdgeType.ETH_TRANSFER
        if tx.tx_type == TransactionType.CONTRACT_CALL:
            edge_type = EdgeType.CONTRACT_CALL

        tx_time = None
        if tx.block_timestamp:
            tx_time = dt.fromtimestamp(tx.block_timestamp)

        self.graph.add_edge(
            from_addr=tx.from_address,
            to_addr=tx.to_address,
            edge_type=edge_type,
            value_eth=tx.value_eth,
            tx_time=tx_time,
            tx_hash=tx.hash,
        )

    def add_token_transfer(self, transfer: 'TokenTransfer'):
        """从代币转账添加边"""
        self.graph.add_edge(
            from_addr=transfer.from_address,
            to_addr=transfer.to_address,
            edge_type=EdgeType.TOKEN_TRANSFER,
            value_eth=0,  # Token转账没有ETH价值
        )

    def build(self) -> AddressGraph:
        """返回构建的图"""
        return self.graph
