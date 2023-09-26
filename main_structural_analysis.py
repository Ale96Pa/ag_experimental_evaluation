import csv, logging, time
import numpy as np
import networkx as nx
import pandas as pd
from pebble import ProcessPool

import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

import config

def write_graphstats(ag_file):
    logging.basicConfig(filename='logging/structural_graphs.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')

    graph_file = config.GRAPH_FOLDER+ag_file
    if not os.path.exists(graph_file): 
        logging.error("File %s NOT exists", ag_file)
        return

    logging.info("[START] %s", ag_file)
    model = ag_file.split("_")[0]
    G = nx.read_graphml(graph_file)

    num_nodes = len(G.nodes())
    num_edges = len(G.edges())

    start_d=time.perf_counter()
    density = nx.density(G)
    end_d=time.perf_counter()
    time_density=end_d-start_d

    start_comp=time.perf_counter()
    num_components = nx.number_strongly_connected_components(G)
    end_comp=time.perf_counter()
    time_components=end_comp-start_comp

    # start_conn=time.perf_counter()
    # node_conn = nx.average_node_connectivity(G)
    # end_conn=time.perf_counter()
    # time_connectivity=end_conn-start_conn
    node_conn=0
    time_connectivity=0
    
    start_deg=time.perf_counter()
    indegree = G.in_degree()
    outdegree = G.out_degree()
    end_deg=time.perf_counter()
    time_degree=end_deg-start_deg
    in_degrees_values = []
    for indeg in indegree:
        in_degrees_values.append(indeg[1])
    out_degrees_values = []
    for outdeg in outdegree:
        out_degrees_values.append(outdeg[1])

    start_cent=time.perf_counter()
    closeness_centrality = nx.closeness_centrality(G)
    between_centrality = nx.betweenness_centrality(G)
    end_cent=time.perf_counter()
    time_centrality=end_cent-start_cent
    closeness_centr_values = []
    for k_cc in closeness_centrality.keys():
        closeness_centr_values.append(closeness_centrality[k_cc])
    between_centr_values = []
    for k_bc in between_centrality.keys():
        between_centr_values.append(between_centrality[k_bc])

    with open(config.STATS_FOLDER+config.get_graph_structure_filename(model), 'a', newline='') as fd:
        params_network_ag = ag_file.split(".graphml")[0].split("_")
        params_network_ag.pop(0)
        params_graph_ag = [num_nodes,num_edges,density,num_components,node_conn,
                           list(np.quantile(in_degrees_values,[0,0.25,0.5,0.75,1])),
                           list(np.quantile(out_degrees_values,[0,0.25,0.5,0.75,1])),
                           list(np.quantile(closeness_centr_values,[0,0.25,0.5,0.75,1])),
                           list(np.quantile(between_centr_values,[0,0.25,0.5,0.75,1])),
                           time_density,time_components,time_connectivity,
                           time_degree,time_centrality                           
                           ]
        writer = csv.writer(fd)
        writer.writerow(params_network_ag+params_graph_ag)
    logging.info("[END] %s", ag_file)
    
if __name__ == "__main__":
    """
    Write the structural graph data for all experiments
    """
    reset_statistics=False
    computed_files = []
    for model in config.ag_models:
        if reset_statistics or not os.path.exists(config.STATS_FOLDER+config.get_graph_structure_filename(model)):
            config.create_graph_structural_file(model, reset_statistics)
        else:
            df=pd.read_csv(config.STATS_FOLDER+config.get_graph_structure_filename(model))
            df["filename"] = model+"_"+df["num_host"].astype(str)+"_"+\
                df["num_vuln"].astype(str)+"_"+df["topology"]+"_"+df['distro_vuln']+\
                "_"+df['diversity_vuln'].astype(str)+'.graphml'
            computed_files+=list(df["filename"])
    for elem in computed_files:
        if "0.0" in elem: 
            newelem = elem.replace("0.0","0")
            computed_files.append(newelem)
        if "1.0" in elem: 
            newelem = elem.replace("1.0","1")
            computed_files.append(newelem)

    filenames = []
    for n in config.nhosts:
        for v in config.nvulns:
            for t in config.topologies:
                for d in config.distro:
                    for u in config.diversity:
                        for model in config.ag_models:
                            filename = model+"_"+str(n)+'_'+str(v)+'_'+t+'_'+d+'_'+str(u)+'.graphml'
                            if os.path.exists(config.GRAPH_FOLDER+filename) and filename not in computed_files:
                                filenames.append(filename)

    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(write_graphstats, filenames)