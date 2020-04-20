# Add Objects and Security Rules into FMC, from CSV files

## Still Under development

- First edit the **fmc_profile.yml** file
- Second test and try to generate an authentication token : **0-fmc_simple_token_request.py**
- Test Rest APIs connectivity to FMC : **1-fmc_system_information.py**  or **2_fmc_get_networks**

### Add Network Objects into FMC

Edit the **network_objects.csv** file and add into it your single network objects

Add these objects into FMC 

- python 4-create_networks_from_csv.py

Edit the **network_groups.csv** file and add into it your network objects groups

Add these objects into FMC 

- python 6-create_networks_groups_from_csv.py

### Add Protocol and Port Objects into FMC

Edit the **service_objects.csv** file and add into it your single protocol and port objects

Add these objects into FMC 

- python 8-create_services_from_csv.py

Edit the **service_object_groupss.csv** file and add into it your protocol objects groups

Add these objects groups into FMC 

- python 9-create_services_groups_from_csv.py
