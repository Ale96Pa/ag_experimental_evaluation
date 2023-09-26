from sentence_transformers import SentenceTransformer

def embed_vulns(vuln_list):
    maxi_str = ""
    for v in vuln_list:
        maxi_str+=v
    return SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2').encode(maxi_str,normalize_embeddings=True)

class Node:
    def __init__(self, privilege, host):
        self.privilege = privilege
        self.host = host

class Edge:
    def __init__(self,src,dst,vuln):
        self.src = src
        self.dst = dst
        self.vulnerability = vuln

class CompactedNode:
    def __init__(self, host):
        self.host = host

class CompactedEdge:
    def __init__(self,src,dst,vuln_list):
        self.src = src
        self.dst = dst
        self.vulnList = vuln_list
        # self.vulnEmbed = embed_vulns(vuln_list)
        # self.vulnHash= hash(tuple(vuln_list))

class AttackGraph:
    def __init__(self,nodes,edges):
        self.nodes = nodes
        self.edges = edges

    def get_node_by_id(self,id):
        for n in self.nodes:
            if n.host["id"] == id:
                return n
            
    def check_if_node_exist(self,node):
        for existing_node in self.nodes:
            if existing_node.host["id"] == node.host["id"] and existing_node.privilege == node.privilege:
                return True
        return False
