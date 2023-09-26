"""
TVA
model: privilege_required -> vulnerability -> privilege_gained
"""
import json, logging, time, csv, random
import networkx as nx
import pandas as pd
from pebble import ProcessPool, ProcessExpired
# from concurrent.futures import TimeoutError
import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import config
from algorithms.utils import retrieve_privileges, get_vulns_from_host

def build_model_graph(network_file):
    with open(config.NETWORK_FOLDER+network_file) as nf:
        content_network = json.load(nf)
    reachability_edges = content_network["edges"]
    devices = content_network["devices"]
    vulnerabilities = content_network["vulnerabilities"]

    G = nx.DiGraph()
    for r_edge in reachability_edges:
        src_id = r_edge["host_link"][0]
        dst_id = r_edge["host_link"][1]
        for host in devices:
            if host["hostname"] == dst_id:
                dst_vulns = get_vulns_from_host(host)
                for v in dst_vulns:
                    vuln,req,gain = retrieve_privileges(v,vulnerabilities)
                    req_node = req+"@"+str(src_id)
                    gain_node = gain+"@"+str(dst_id)
                    vuln_node = vuln["id"]

                    if req_node not in G.nodes(): G.add_node(req_node, type="privilege", color="green")
                    if gain_node not in G.nodes(): G.add_node(gain_node, type="privilege", color="green")
                    if vuln_node not in G.nodes(): G.add_node(vuln_node, type="vulnerability", color="blue")
                    if (req_node, vuln_node) not in G.edges(): G.add_edge(req_node, vuln_node)
                    if (vuln_node, gain_node) not in G.edges(): G.add_edge(vuln_node, gain_node)
    nx.write_graphml_lxml(G, config.GRAPH_FOLDER+"TVA_"+network_file.split(".json")[0]+".graphml")

def forward_step(G, S_init):
    S_found = []
    for source in S_init:
        for edge in nx.edge_bfs(G, source, orientation="original"):
            S_found.append(edge[:2])
    return nx.DiGraph(S_found)

def backward_step(D_init, S_goal):
    conjunctions = []
    new_dest = S_goal.copy()
    considered = []
    S_found=[]
    while len(new_dest) > 0:
        goal = new_dest.pop(0)
        if goal not in considered:
            disjunction = []
            for edge in nx.bfs_edges(D_init, goal, reverse=True):
                S_found.append(edge)
                disjunction.append(edge)
                new_dest.append(edge[1])
            conjunctions.append(disjunction)
            considered.append(goal)
    return conjunctions, nx.DiGraph(S_found)

# def tva_generation(params):
#     ag_file, G, S_init, S_goal, generate_paths = params
#     logging.basicConfig(filename='tva.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')
#     df = pd.read_csv(config.STATS_FOLDER+config.generation_stats_file)
#     mod,nhost,nvuln,topo,distro,diver = ag_file.split(".graphml")[0].split("_")
#     num_sources = len(S_init)
#     num_targets = len(S_goal)
#     df_exist = df.loc[(df['model']=="TVA") & 
#              (df['num_host']==nhost) & 
#              (df['num_vuln']==nvuln) &
#              (df['topology']==topo) &
#              (df['distro_vuln']==distro) &
#              (df['diversity_vuln']==diver) &
#              (df['num_entries']== num_sources)&
#              (df['num_targets']== num_targets)]
#     if len(df_exist)>0: 
#         logging.debug("Already generated experiment: %s", ag_file)
#         print(ag_file)
#         return 0


#     logging.info("Starting TVA generation: %s", ag_file)
#     try:
#         start = time.perf_counter()

#         D_init = forward_step(G, S_init)
#         steps = backward_step(D_init, S_goal)

#         attack_paths = []
#         if generate_paths:
#             print("start generation")
#             src_steps = steps[0]
#             dst_steps = steps[1]
#             for s in src_steps:
#                 for d in dst_steps:
#                     if s[1] == d[0]:
#                         attack_paths.append([s[0],s[1],d[1]])
#             print("first_step", len(attack_paths))
#             src_steps = dst_steps
#             for i in range(2,len(steps)):
#                 dst_steps = steps[i]
#                 for p in attack_paths:
#                     for d in dst_steps:
#                         if p[len(p)-1] == d[0]:
#                             p_cpy = p.copy()
#                             p_cpy.append(d[1])
#                             attack_paths.append(p_cpy)
#                 print("step ",i, len(attack_paths))
#         else:
#             for disjunction in steps:
#                 attack_paths+=disjunction
#         end = time.perf_counter()

#         num_paths = len(attack_paths) if generate_paths else len(steps)
#         generation_time = end-start
#         with open(config.STATS_FOLDER+config.generation_stats_file,'a',newline='') as fd:
#             params_network_ag = ag_file.split(".graphml")[0].split("_")+[num_sources,num_targets,num_paths,generation_time,generate_paths]
#             writer = csv.writer(fd)
#             writer.writerow(params_network_ag)
#     except e:
#         print(e)
#         logging.error("[ERROR] %s on file %s", e, ag_file)
#         with open(config.STATS_FOLDER+config.generation_stats_file,'a',newline='') as fd:
#             params_network_ag = ag_file.split(".graphml")[0].split("_")+[num_sources,num_targets,num_paths,generation_time,generate_paths]
#             writer = csv.writer(fd)
#             writer.writerow(params_network_ag)
    
#     logging.info("WRITTEN TVA generation: %s", ag_file)
#     print(len(attack_paths))
#     return len(attack_paths)
def tva_generation(params):
    ag_file, G, S_init, S_goal, generate_paths = params
    print(ag_file,len(G.nodes()),len(G.edges()))
    logging.basicConfig(filename='tva.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')
    
    df = pd.read_csv(config.STATS_FOLDER+config.generation_stats_file)
    mod,nhost,nvuln,topo,distro,diver = ag_file.split(".graphml")[0].split("_")
    num_sources = len(S_init)
    num_targets = len(S_goal)
    df_exist = df.loc[(df['model']==mod) & 
             (df['num_host']==nhost) & 
             (df['num_vuln']==nvuln) &
             (df['topology']==topo) &
             (df['distro_vuln']==distro) &
             (df['diversity_vuln']==diver) &
             (df['num_entries']==num_sources)&
             (df['num_targets']==num_targets)]
    if len(df_exist)>0: 
        logging.debug("Already generated experiment: %s", ag_file)
        print(ag_file)
        return 0

    logging.info("Starting TVA generation: %s", ag_file)
    try:
        start = time.perf_counter()

        D_init = forward_step(G, S_init)
        steps,G_filtered = backward_step(D_init, S_goal)
        print(len(G_filtered.nodes()),len(G_filtered.edges()))

        attack_paths = []
        if generate_paths:
           for source in S_init:
               for dest in S_goal:
                    print(source,dest)
                    for path in nx.all_simple_paths(G_filtered,source,dest):
                        attack_paths.append(path)
        end = time.perf_counter()

        num_paths = len(attack_paths) if generate_paths else len(steps)
        generation_time = end-start
        with open(config.STATS_FOLDER+config.generation_stats_file,'a',newline='') as fd:
            params_network_ag = ag_file.split(".graphml")[0].split("_")+[num_sources,num_targets,num_paths,generation_time,generate_paths]
            writer = csv.writer(fd)
            writer.writerow(params_network_ag)
    except e:
        print(e)
        logging.error("[ERROR] %s on file %s", e, ag_file)
        with open(config.STATS_FOLDER+config.generation_stats_file,'a',newline='') as fd:
            params_network_ag = ag_file.split(".graphml")[0].split("_")+[num_sources,num_targets,num_paths,generation_time,generate_paths]
            writer = csv.writer(fd)
            writer.writerow(params_network_ag)
    
    logging.info("WRITTEN TVA generation: %s", ag_file)
    return len(attack_paths)

if __name__ == "__main__":
    logging.basicConfig(filename='tva.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')
    config.create_generation_stats_file(True)
    model = "TVA"
    generate_path = config.generate_all_paths

    parameters = []
    for ag_file in os.listdir(config.GRAPH_FOLDER):
        if model in ag_file:
            graph_file = config.GRAPH_FOLDER+ag_file
            try:
                G = nx.read_graphml(graph_file)
                state_nodes=[]
                for n in G.nodes():
                    if "CVE" not in n:state_nodes.append(n)

                for num_src in config.num_entry_points+[len(state_nodes)-1]:
                    if num_src > len(state_nodes): num_s = len(state_nodes)-1
                    else: num_s = num_src
                    for num_trg in config.num_entry_points+[len(state_nodes)-1]:
                        if num_trg > len(state_nodes): num_t = len(state_nodes)-1
                        else: num_t = num_trg
                        
                        S_init = random.sample(list(state_nodes),num_s)
                        S_goal = random.sample(list(state_nodes),num_t)
                        # for n in G.nodes():
                        #     if n not in S_init: S_goal.append(n)
                        #     if len(S_goal) == num_t: break
                        parameters.append([ag_file,G,S_init,S_goal,generate_path])
                
            except Exception as e:
                logging.error("%s", e)
                logging.error("File NOT writter: %s", ag_file)

    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(tva_generation, parameters, timeout=config.timeout)
