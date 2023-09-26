import os, time, csv, logging
from pebble import ProcessPool
import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))

from generate_full_storage import generate_intentory
from generate_reachability import write_reachability
import algorithms.tva as TVA
import algorithms.netspa as NETSPA
import config

"""
Generate the benchmark of networks in "network" folder
"""
def generate_network(filename):
    logging.basicConfig(filename='logging/network.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')

    if not os.path.exists(config.NETWORK_FOLDER): os.makedirs(config.NETWORK_FOLDER)
    generated_files = os.listdir(config.NETWORK_FOLDER)
    if filename not in generated_files:
        write_reachability(config.NETWORK_FOLDER,filename)
        logging.info("Generated network: %s (total generated files - %d)", filename, len(generated_files))
    else:
        logging.debug("[Already Generated]: %s (total generated files - %d)", filename, len(generated_files))

"""
Generate the benchmark of attack graphs models in "attack_graphs" folder
"""
def generate_ag_models(params):
    filename, model = params
    logging.basicConfig(filename='logging/agmodel.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s: %(message)s')

    if not os.path.exists(config.GRAPH_FOLDER): os.makedirs(config.GRAPH_FOLDER)
    generated_files = os.listdir(config.GRAPH_FOLDER)

    if model == "NETSPA":
        if "NETSPA_"+filename.split(".json")[0]+".graphml" not in generated_files:
            logging.info("Starting generation of NetSPA, file %s", filename)
            start_netspa = time.perf_counter()
            NETSPA.build_model_graph(filename)
            end_netspa = time.perf_counter()
            generation_time = end_netspa-start_netspa
            with open(config.STATS_FOLDER+config.graph_stats_file,'a',newline='') as fd:
                params_network_ag = [model]+filename.split(".json")[0].split("_")+[generation_time]
                writer = csv.writer(fd)
                writer.writerow(params_network_ag)
            logging.info("[NETSPA GENERATED] %s", filename)
        else: logging.debug("Already generated NETSPA %s", filename)
    elif model == "TVA":
        if "TVA_"+filename.split(".json")[0]+".graphml" not in generated_files:
            logging.info("Starting generation of TVA, file %s", filename)
            start_tva = time.perf_counter()
            TVA.build_model_graph(filename)
            end_tva = time.perf_counter()
            generation_time = end_tva-start_tva
            with open(config.STATS_FOLDER+config.graph_stats_file,'a',newline='') as fd:
                params_network_ag = [model]+filename.split(".json")[0].split("_")+[generation_time]
                writer = csv.writer(fd)
                writer.writerow(params_network_ag)
            logging.info("[TVA GENERATED] %s", filename)
        else: logging.debug("Already generated TVA %s", filename)

if __name__ == "__main__":
    """
    To build the inventory from skratch
    NOTICE: this may require long time for NIST APIs. We suggest to use the 
    proposed syntetic inventory
    """
    # generate_intentory()

    """
    Create networks for reachability graphs
    """
    parameters = []
    filenames=[]
    for n in config.nhosts:
        for v in config.nvulns:
            for t in config.topologies:
                for d in config.distro:
                    for u in config.diversity:
                        filename = str(n)+'_'+str(v)+'_'+t+'_'+d+'_'+str(u)+'.json'
                        filenames.append(filename)
                        for model in config.ag_models: 
                            parameters.append([filename, model])

    """
    Generate Reachability Networks
    """
    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(generate_network, filenames)

    """
    Generate Attack Graphs models
    """
    config.create_graph_stats_file()
    with ProcessPool(max_workers=config.num_cores) as pool:
        process = pool.map(generate_ag_models, parameters)
