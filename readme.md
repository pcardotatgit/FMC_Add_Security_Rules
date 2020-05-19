# Add Objects and Security Rules into FMC, from CSV files

## Introduction

The purpose of this set of scripts is to automate the Network Objects, Ports Objects and Security Rules creation into FMC.

The goal is to be able to create into FirePOWER Management Center, thousands of Objects and Security Rules from CSV files.

## Installation

Installing these scripts is pretty straight forward . You can just copy / and paste them into you python environment but a good practice is to run them into a python virtual environment.

### Install a Python virtual environment

	For Linux/Mac 

	python3 -m venv venv
	source bin activate

	For Windows 
	
	We assume that you already have installed git-bash.  If so open a git-bash console and :

	ptyhon -m venv env 
	source /venv/Scripts/activate

### git clone the scripts

	git clone https://github.com/pcardotatgit/FMC_Add_Security_Rules.git
	cd FMC_Add_Security_Rules/
	
### install needed modules

FMC_Add_Security_Rules uses the following modules

- requests
- pyyaml
- json
- csv
- pprint
- crayons
	
you can install them with the following  :
	
	pip install -r requirements.txt

## How to use the scripts

- First edit the **fmc_profile.yml** file
- Second test and try to generate an authentication token : **0-fmc_simple_token_request.py**
- Test Rest APIs connectivity to FMC : **1-fmc_system_information.py**  or **2_fmc_get_networks**

The **fmc_profile.yml** is a configuration file which contains FMC's IP address, api admin username and password, listening port and API version

Every script starts by reading this file

### Ask for an authentication token to FMC ###

Run the **0-fmc_simple_token_request.py** file.  

It will generate a valid authentication token which will be stored into the **token.txt** file.

This authentication token will be valid during 30 minutes. 

All scripts will read the authentication token from the **token.txt** file and if the token is no longer valid ( error code 401 ), all scripts will automatically ask to FMC for a new authentication token.

### Display the Existing Network Objects ###

Run the **2-fmc_get_networks.py ** script.

This script displays all non system network objects and store them into the **network_objects.txt** file

As the maximum number of objects FMC can return is limited to 1000, the script manages to run a loop which reads the whole FMC network object database.

Thanks to this, this script can output thousands of objects FMC could contain.

### Add Network Objects into FMC ###

The **network_objects.csv** file contains all single network objects to add into FMC. Open it and have a look at it.

Don't hesistate to add additional network objects

Add these objects into FMC 

Run the ** python 4-create_networks_from_csv.py ** script.

This manages automatically all error conditions during post calls.

- If the authentication expires, then a new token will be generated
- Every post will contains an maximum of 1000 objects ( max_objects variable at the begining of the script ). A loop will send all objects
- It manages rate limit to 120 calls per minutes
- If an POST error occurs due to a malformed or invalid JSON post data, then the stops and the error is logged into the ** error.txt ** file
- After having correcting errors, you can run again the script and it will start at the last object it succeeded to create in FMC

Thank to all this, this script can create thousands of network objects into FMC

### Delete Network Objects ###

The ** 5-fmc_delete_networks.py ** file is an example of how to delete network objects.

it deletes all objects contained into the ** network_objects.txt ** file ( generated by the **2-fmc_get_networks.py ** script )

### Create Network Object Group ###

First edit the **network_groups.csv** file and add into it your network objects groups

And then run the **python 6-create_networks_groups_from_csv.py** file

### Add Protocol and Port Objects into FMC ###

All the following scripts works exactly the same as the scripts used for creating network objects

For single port objects :
- Edit the **service_objects.csv** file and add into it your single protocol and port objects
- Run the **python 8-create_services_from_csv.py** script

For port object groups :

- Edit the **service_object_groupss.csv** file and add into it your protocol objects groups
- run the **python 9-create_services_groups_from_csv.py** script.

- **7-fmc_get_services.py** displays all port objects FMC contains and store the result into the **service_objects.txt** file
- **10-fmc_delete_services.py** deletes all ports objects contained into the **service_objects.txt** file

### Access Control Policies and Security Rules ###

- **11-fmc_get_access_control_policies.py** displays all existing Access Control Policies
- **12-create_an_acp.py** creates and Access Control Policy
- **13-fmc_get_access_rules.py** displays all Security Rules contained into a ACP
- **14-create_a_single_security_rule_in_acp.py** Creates a single security rule into an ACP
 