# Experimental Evaluation of Attack Graph Scalability

## Requirements:

The following libraries and packages are required for the correct installation of the benchmark:

- pandas
- networkx
- pebble
- numpy
- matplotlib

## Instructions

### 1. Set up the inventory:

The inventory folder must contain a file with the CPEs and one (ore more, up to three) file with the CVEs. We provide a sample of these files in the inventory folder. In addition, you can find the scripts to generate them in generate_full_storage.py file

### 2. Build the network inventories and attack graph models:

```
python3 main_graph_generation.py
```

Run the main graph generation to generate both the network inventories (reachability graphs and vulnerability inventories) and the attack graph models according to NetSPA and TVA. The results of this module is the inventory (in json format) and related attack graphs (in graphml format) in two appropriate folders: "networks" and "attack_graphs" respectively.

MulVAL is excluded by default, if you want to add MulVAL in the analysis, update the config.py file. More information available in the next section "Instructions for MulVAL".
NOTICE: MulVAL must be generated using the propietary tool available at: https://people.cs.ksu.edu/~xou/mulval/

### 3. Compute graph structural analysis

```
python3 main_structural_analysis.py
```

Run the structural analysis module to retrieve graph properties of attack graph (e.g., centrality, connectivity, strong components). The results will be available for each model in an appropriate file in the "analysis" folder.

### 4. Compute attack paths

```
python3 main_path_analysis.py
```

Run the path analysis module to compute the possible attack paths for each generate attack graph storing information about scalability (i.e., computation time and number of paths).

### 5. Analyze the results

```
python3 main_plot_analysis.py
```

Some precomputed plots are available in main_plot_analysis.py script.

# Instructions for MulVAL

Since MulVAL is tested used the proprietary project (https://people.cs.ksu.edu/~xou/mulval/), some further steps are necessary for the analysis of it.

NOTICE: MulVAL is available only for Linux os.

### 1. Install MulVAL

### 2. Generate MulVAL inputs

```
python3 algorithms/mulval.py
```

After the generation of network inventories (step2 of previous section), uncomment the first part of the main module from the script "algorithms/mulval.py": it generates the inputs for the MulVAL project according to the required format in the "mulval_inputs" folder.

### 3. Generate MulVAL attack graph

Generate the attack graph according to MulVAL project instruction. We provide a bash script to auotmatically process input files. The file "exec_mulval.sh" pick files from a folder "dataset" and generate attack graph automatically, keeping track of the required generation time in the "time_log.txt" file. It works with a slight modification of the MulVAL main that we also provide in the mulval_util folder.

Once processed, put all the generated ARCS.csv, VERTICES.csv, and AttackGraph.txt files in the "mulval_output" folder, and the file "time_log.txt" in the analysis folder.

### 4. Generate MulVAL graph-based models

```
python3 algorithms/mulval.py
```

Uncomment the second part of the main module of the script "algorithms/mulval.py": it generates the graphml representation of MulVAL attack graphs.

### 5. Compute structural and path analyses

Perform the steps of the previous section starting from 3.
