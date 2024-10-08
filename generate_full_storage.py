import nvdlib, time, json, os
from config import cpe_file

def getCPElist(cpe_file):
    server_cpe = nvdlib.searchCPE(keywordSearch="mysql", limit=2000)
    # time.sleep(6)
    windows_cpe = nvdlib.searchCPE(keywordSearch="windows", limit=2000)
    # time.sleep(6)
    linux_cpe = nvdlib.searchCPE(keywordSearch="linux", limit=2000)
    # time.sleep(6)
    oracle_cpe = nvdlib.searchCPE(keywordSearch="oracle", limit=2000)
    # time.sleep(6)
    apache_cpe = nvdlib.searchCPE(keywordSearch="apache", limit=2000)
    
    with open(cpe_file, "w") as outfile:
        json_data = json.dumps({"services":server_cpe+windows_cpe+linux_cpe+
                                oracle_cpe+apache_cpe
                                }, 
                                default=lambda o: o.__dict__, indent=2)
        outfile.write(json_data)
    # return server_cpe+windows_cpe+linux_cpe+oracle_cpe+apache_cpe

def getCVElist(cpe_file, cve_file):
    with open(cpe_file) as cpef:
        services = json.load(cpef)["services"]
    all_cves=[]
    written = 0
    count=0
    for cpe in reversed(services):
        time.sleep(6)
        cve_list = nvdlib.searchCVE(cpeName = cpe["cpeName"], limit=2000)
        for curr_cve in cve_list:
            if len(curr_cve)>0:
                all_cves.append(curr_cve)

        if count == 100:        
            with open(cve_file+str(len(all_cves))+".json", "w") as outfile:
                json_data = json.dumps({"vulnerabilities":all_cves}, 
                                        default=lambda o: o.__dict__, indent=2)
                outfile.write(json_data)
                written=len(all_cves)
                print(written)

        if count == 200:        
            with open(cve_file+str(len(all_cves))+".json", "w") as outfile:
                json_data = json.dumps({"vulnerabilities":all_cves[written+1:len(all_cves)]}, 
                                        default=lambda o: o.__dict__, indent=2)
                outfile.write(json_data)
                written=len(all_cves)
                print(written)
        
        if count == 300:
            with open(cve_file+str(len(all_cves))+".json", "w") as outfile:
                json_data = json.dumps({"vulnerabilities":all_cves[written+1:len(all_cves)]}, 
                                        default=lambda o: o.__dict__, indent=2)
                outfile.write(json_data)
                written=len(all_cves)
                print(written)

        if count == 400:
            with open(cve_file+str(len(all_cves))+".json", "w") as outfile:
                json_data = json.dumps({"vulnerabilities":all_cves[written+1:len(all_cves)]}, 
                                        default=lambda o: o.__dict__, indent=2)
                outfile.write(json_data)
                written=len(all_cves)
                print(written)
            break

        count+=1

# def getCVElist_smart():
#     all_cves=[]
#     cve_list = nvdlib.searchCVE(keywordSearch="2013", limit=2000)
#     for curr_cve in cve_list:
#         if len(curr_cve)>0:
#             all_cves.append(curr_cve)
#     with open(cve_file+"smart3.json", "w") as outfile:
#         json_data = json.dumps({"vulnerabilities":all_cves}, 
#                                 default=lambda o: o.__dict__, indent=2)
#         outfile.write(json_data)
#     print(len(all_cves))

def generate_intentory():
    if not os.path.exists("inventory"): os.mkdir("inventory")
    
    getCPElist(cpe_file)
    print("created CPE file")
    for i in range(1,4):
        getCVElist(cpe_file, "inventory/vulnerabilities"+str(i)+".json")
        print("created CVE file")