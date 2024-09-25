import json, sys, os
from scipy import stats
import numpy as np
import networkx as nx

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
from algorithms.utils import get_vulns_from_host
from generate_reachability import build_topology

IT_NET="real_network/it_department.json"
V2X_NET="real_network/v2x_network.json"
PANACEA_NET="real_network/medical_panacea.json"

def check_size(devices):
    num_host=len(devices)
    num_vuln=[]
    for host in devices:
        vulns=get_vulns_from_host(host)
        num_vuln.append(len(vulns))
    num_unique_vuln=sum(num_vuln)
    
    return num_host, num_unique_vuln, round(sum(num_vuln)/len(num_vuln))

def check_vuln_distro(devices):
    vuln_distro=[]
    for host in devices:
        vulns=get_vulns_from_host(host)
        vuln_distro.append(len(vulns))
    if len(vuln_distro)<=9: vuln_distro+=vuln_distro+vuln_distro

    sample_uniform = np.random.uniform(min(vuln_distro), max(vuln_distro), size=len(vuln_distro))
    sample_pareto = np.random.pareto(len(vuln_distro), size=len(vuln_distro)) 
    sample_binomial = np.random.binomial(len(vuln_distro), 0.5, size=len(vuln_distro))
    sample_poisson = np.random.poisson(len(vuln_distro), size=len(vuln_distro))


    vuln_distro.sort()
    ks_uniform=stats.ks_2samp(vuln_distro,np.sort(sample_uniform))
    ks_pareto=stats.ks_2samp(vuln_distro,np.sort(sample_pareto))
    ks_binomial=stats.ks_2samp(vuln_distro,np.sort(sample_binomial))
    ks_poisson=stats.ks_2samp(vuln_distro,np.sort(sample_poisson))
    results={
        "uniform": ks_uniform.statistic,
        "pareto": ks_pareto.statistic,
        "binomial": ks_binomial.statistic,
        "poisson": ks_poisson.statistic,
    }
    min_k = min(results, key=results.get)
    return min_k, results[min_k]

def check_diversity(devices):
    vuln_distro={}
    for host in devices:
        vulns=get_vulns_from_host(host)
        vuln_distro[host["id"]]=vulns
    
    jaccards=[]
    for k1 in vuln_distro.keys():
        for k2 in vuln_distro.keys():
            if k1 != k2:
                set1 = set(vuln_distro[k1])
                set2 = set(vuln_distro[k2])
                if len(set1.union(set2)) > 0:
                    jac_sim = float(len(set1.intersection(set2)) / len(set1.union(set2)))
                    jaccards.append(jac_sim)
    return 1-(sum(jaccards)/len(jaccards))

def check_topology(netfile,edges):
    G=nx.DiGraph()
    format_edges=[]
    if "v2x" in netfile: G = nx.from_edgelist(edges)
    elif "panacea" in netfile:
        for e in edges:
            format_edges.append(e["host_link"])
        G = nx.from_edgelist(format_edges)
    elif "department" in netfile:
        for e in edges:
            format_edges.append(e["id_link"])
        G = nx.from_edgelist(format_edges)

    results={}
    for topology in ["mesh",'random','star','ring','tree','powerlaw','lan0','lan25','lan50']:
        G_top = build_topology(topology,list(G.nodes))
        geds = nx.optimize_graph_edit_distance(G_top,G)
        for ged in geds:
            results[topology]=ged/len(G.edges)#/max([len(G.edges),len(G_top.edges)])
            break
    
    min_k = min(results, key=results.get)
    return min_k, results[min_k]

if __name__ == "__main__":

    for netfile in [V2X_NET,PANACEA_NET,IT_NET]:
        with open(netfile) as nf: content_network = json.load(nf)
        devices=content_network["devices"]
        vulnerabilities=content_network["vulnerabilities"]
        edges=content_network["edges"]

        print(netfile)
        num_host, num_unique_vuln, num_vuln = check_size(devices)
        print("Num. host: ", num_host, "\nNum. total vuln: ", num_unique_vuln, "\nNum. vuln per host: ", num_vuln)
        
        res_experiments=[]
        for i in range(0,300):
            distro, ks_distance = check_vuln_distro(devices)
            res_experiments.append({distro: ks_distance})
        min_ks = 1
        min_distro = "none"
        for ks_dct in res_experiments:
            ks_dict_k = list(ks_dct.keys())[0]
            if ks_dct[ks_dict_k] < min_ks: 
                min_ks = ks_dct[ks_dict_k]
                min_distro = ks_dict_k
        print("Distro: ", min_distro, " - Similarity: ", 1-min_ks)
        
        diversity = check_diversity(devices)
        print("Diversity: ", diversity)

        res_experiments=[]
        for i in range(0,20):
            topology, ged = check_topology(netfile,edges)
            res_experiments.append({topology: ged})
        min_ged = 1
        min_topology = "none"
        for ks_dct in res_experiments:
            ks_dict_k = list(ks_dct.keys())[0]
            if ks_dct[ks_dict_k] < min_ged: 
                min_ged = ks_dct[ks_dict_k]
                min_topology = ks_dict_k
        print("Topology: ", min_topology, " - Similarity: ", min_ged)
        print("\n")
    