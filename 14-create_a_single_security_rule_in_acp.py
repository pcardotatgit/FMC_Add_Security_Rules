#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Copyright (c) 2020 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

			   https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

What is this :
	This script is an example of creation of a single access control policy
'''
import json
import sys
import requests
import yaml
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from pprint import pprint, pformat
from pathlib import Path
from crayons import blue, green, white, red, yellow,magenta, cyan

#acp="PAT_Access_Control_Policy"
max_objects=100 #max number of object to send to FMC in a single POST Call
new_auth_token=[]#as global variable in order to make it easily updatable 
new_auth_token.append("zzz") 
existing_name_list=[] # List of existing names into FMC 
limit=5000 #number of object to retrieve from FMC in a single GET cal
go_create_object=0 # for debuggin 1=send new object to FMC  0=dont

post_data_example={
  "action": "[ ALLOW, TRUST, BLOCK, MONITOR, BLOCK_RESET, BLOCK_INTERACTIVE, BLOCK_RESET_INTERACTIVE ]",
  "enabled": True,
  "type": "AccessRule",
  "name": "Rule1",
  "sendEventsToFMC": False,
  "logFiles": False,
  "logBegin": False,
  "logEnd": False,
  "variableSet": {
    "name": "Default Set",
    "id": "VariableSetUUID",
    "type": "VariableSet"
  },
  "vlanTags": {
    "objects": [
      {
        "type": "VlanTag",
        "name": "vlan_tag_1",
        "id": "VlanTagUUID1"
      },
      {
        "type": "VlanTag",
        "name": "vlan_tag_2",
        "id": "VlanTagUUID2"
      }
    ]
  },
  "urls": {
    "urlCategoriesWithReputation": [
      {
        "type": "UrlCategoryAndReputation",
        "category": {
          "name": "Weapons",
          "id": "URLCategoryUUID",
          "type": "URLCategory"
        },
        "reputation": "BENIGN_SITES_WITH_SECURITY_RISKS"
      }
    ]
  },
  "sourceZones": {
    "objects": [
      {
        "name": "External",
        "id": "SecurityZoneUUID",
        "type": "SecurityZone"
      }
    ]
  },
  "destinationZones": {
    "objects": [
      {
        "name": "Internal",
        "id": "SecurityZoneUUID",
        "type": "SecurityZone"
      }
    ]
  },
  "sourcePorts": {
    "objects": [
      {
        "type": "ProtocolPortObject",
        "name": "AOL",
        "id": "ProtocolPortObjectUUID"
      }
    ]
  },
  "destinationPorts": {
    "objects": [
      {
        "type": "ProtocolPortObject",
        "name": "Bittorrent",
        "id": "ProtocolPortObjectUUID"
      }
    ]
  },
  "ipsPolicy": {
    "type": "IntrusionPolicy",
    "id": "ipsPolicyUuid",
    "name": "ipsPlicyName"
  },
  "filePolicy": {
    "type": "FilePolicy",
    "id": "filePolicyUuid",
    "name": "filePolicyName"
  },
  "snmpConfig": {
    "id": "snmpConfigUuid",
    "name": "snmp_alert1",
    "type": "SNMPAlert"
  },
  "syslogConfig": {
    "id": "syslogConfigUuid",
    "name": "syslog_alert1",
    "type": "SyslogAlert"
  },
  "newComments": [
    "comment1",
    "comment2"
  ]
}


def generate_fmc_token(host,port,username,password,version):
	r = None
	headers = {'Content-Type': 'application/json'}
	api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
	auth_url = 'https://'+host+':'+str(port)+ api_auth_path
	
	try:
	#Token Generation
	#To enable Certificate validation change verify=False to verify=path/to/certificate
		r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
		auth_headers = r.headers
		auth_token = auth_headers.get('X-auth-access-token', default=None)
		DOMAIN_UUID = auth_headers.get('global', default=None)
		
		if auth_token == None:
			print("auth_token not found. Exiting...")
			sys.exit()
	except Exception as err:
		print ("Error in generating auth token --> "+str(err))
		sys.exit()
	#save the token into a text file
	fh = open("token.txt", "w")
	fh.write(auth_token)
	fh.write("\r\n")
	fh.write(DOMAIN_UUID)
	fh.close() 
	new_auth_token[0]=auth_token
	print (green("Token = "+auth_token))
	print(green("DOMAIN_UUID="+DOMAIN_UUID))
	print("Saved into token.txt file")
	
def fmc_get(host,port,token,UUID,url,version,username,password,offset):
	'''
	This is a GET request to obtain the list of all Network Objects in the system.
	'''
	headers = {
		"Content-Type": "application/json",
		"Accept": "application/json",
		"X-auth-access-token":"{}".format(token)
	}

	try:
		request = requests.get("https://{}:{}/api/fmc_config/v{}/domain/{}{}?expanded=true&offset={}&limit={}".format(host, port,version,UUID,url,offset,limit),verify=False, headers=headers)
		status_code = request.status_code		
		print("Status code is (1): "+str(status_code))
		if status_code == 401: 
			print("Let's ask for a new token")
			generate_fmc_token(host,port,username,password,version)	
			line_content = []
			with open('token.txt') as inputfile:
				for line in inputfile:
					if line.strip()!="":	
						line_content.append(line.strip())						
			auth_token = line_content[0]
			headers['X-auth-access-token']=auth_token			
			request = requests.get("https://{}:{}/api/fmc_config/v{}/domain/{}{}?expanded=true&offset={}&limit={}".format(host, port,version,UUID,url,offset,limit),verify=False, headers=headers)
			status_code = request.status_code
		resp = request.text
		if status_code == 200 or status_code == 201 or status_code == 202:
			print ('OK')
		return request.json()
	except:
		raise
			

def fmc_post(host,port,token,UUID,url,version,post_data):
	url = "https://{}:{}/api/fmc_config/v{}/domain/{}{}".format(host, port,version,UUID,url)
	try:
		# REST call with SSL verification turned off: 
		r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
		
		print(url)
		# REST call with SSL verification turned on:
		# r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
		status_code = r.status_code
		resp = r.text
		print("Status code is: "+str(status_code))
		if (status_code == 429):
			print(cyan(" Let's Wait 60 Sec ! before sending again JSON Data to FMC"))
			print(cyan(" Too many requests were sent to the API. This error will occur if you send more than 120 requests per minute."))
			print(cyan(" Too many concurrent requests. The system cannot accept more than 10 parallel requests from all clients."))
			print(cyan(" Too many write operations per server. The API will only allow one PUT, POST, or DELETE request per user on a server at a time. "))
			time.sleep(60)
			# Send again data to FMC
			r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
			status_code = r.status_code			
		if status_code == 422: 
			print(red("Something is wrong into JSON Data sent to FMC - check values. open error.log",bold=True))	
			print(red("Let's exit in order to debug Data",bold=True))
			print(cyan("Remark ",bold=True))
			print(cyan("The payload is too large. This will occur when you send a payload greater than 2048000 bytes."))
			print(cyan("The payload contains an unprocessable or unreadable entity such as a invalid attribut name or incorrect JSON syntax."))
			resp = r.text			
			print (red("Error occurred in POST --> "+resp,bold=True))
			fh = open("error.log", "a+")
			fh.write(resp)
			fh.write("\n")			
			fh.write("=========================================")
			fh.write("\n")
			fh.write(json.dumps(post_data,indent=4,sort_keys=True))
			fh.close()
			sys.exit()		
		if status_code == 400: 
			print(red("Something is wrong into JSON Data sent to FMC - check values. open error.log",bold=True))	
			print(red("Let's exit in order to debug Data",bold=True))
			print(cyan("Remark ",bold=True))
			print(cyan(" This kind of error could be due to a forbiden character into a name. For example the space characater. It is better to replace spaces by underscores.  Or forbiden syntax in the values. For example if you try to create a range with Start which is less than the End. Then you will have an error. you will have an error as well if you try to create an object wich already exists"))
			print(cyan(" An error could occur as well with anygood reason !  Then just try to run again the script and check if it fails at the same Data after a few tries. If so, then debug the Data.  But you will be probably able to the Data which previously failed !"))
			print(cyan(" This script will automatically restart from the last object you created in the previous try"))
			print(cyan(" Then you can launch the script several times until all your object are created"))
			resp = r.text			
			print (red("Error occurred in POST --> "+resp,bold=True))
			fh = open("error.log", "a+")
			fh.write(resp)
			fh.write("\n")			
			fh.write("=========================================")
			fh.write("\n")
			fh.write(json.dumps(post_data,indent=4,sort_keys=True))
			fh.close()
			sys.exit()
		if status_code == 401: 
			print("Let's ask for a new token (1)")
			generate_fmc_token(host,port,username,password,version)	
			line_content = []
			with open('token.txt') as inputfile:
				for line in inputfile:
					if line.strip()!="":	
						line_content.append(line.strip())						
			auth_token = line_content[0]
			headers['X-auth-access-token']=auth_token			
			r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text			
		if status_code == 201 or status_code == 202:
			print ("Post was successful...")
			json_resp = json.loads(resp)
			print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
		else :
			r.raise_for_status()
			print ("Error occurred in POST --> "+resp)
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r: r.close()


def yaml_load(filename):
	fh = open(filename, "r")
	yamlrawtext = fh.read()
	yamldata = yaml.load(yamlrawtext)
	return yamldata

if __name__ == "__main__":
	FMC_Server = {}
	FMC_Server = yaml_load("FMC_profile.yml")
	print()
	print(yellow("Get system information of FMC Server  :", bold=True))
	pprint(FMC_Server["FMC_Server"])	
	#pprint(FMC_Server["FMC_Server"][0]['ipaddr'])
	FMC_USER = FMC_Server["FMC_Server"][0]['username']
	FMC_PASSWORD = FMC_Server["FMC_Server"][0]['password']
	FMC_IPADDR = FMC_Server["FMC_Server"][0]['ipaddr']
	FMC_PORT = FMC_Server["FMC_Server"][0]['port']
	FMC_VERSION = FMC_Server["FMC_Server"][0]['version']
	print()
	server = "https://"+FMC_IPADDR+':'+str(FMC_PORT)

	line_content = []
	with open('token.txt') as inputfile:
		for line in inputfile:
			if line.strip()!="":	
				line_content.append(line.strip())
				
	auth_token = line_content[0]
	DOMAIN_UUID = line_content[1]	
	new_auth_token[0]=auth_token
	
	print ('auth_token :',auth_token)
	print ('UUID : ',DOMAIN_UUID)

	headers = {'Content-Type': 'application/json'} 
	headers['X-auth-access-token']=auth_token
	print('==========================================================================================')	
	print(yellow("Step - 1 : Get ACPs list ",bold=True))			
	go=1
	offset=0
	ii=0	
	while go==1:
		# List Network Addesses Objects ( host and ip addresses )
		auth_token=new_auth_token[0]
		api_url="/policy/accesspolicies"
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		# save json output
		#output=json.dumps(objets,indent=4,sort_keys=True)
		#print(output)
		#fa.write(output)
		print()
		acp_list={}
		if objets.get('items'):
			ii=0
			for line in objets['items']:
				ii+=1
				condition=1
				#check here for a condition to save result		
				if condition==1:	
					print(str(ii), ' - ' , line['name'],' id = ',line['id'])	
					acp_list.update({str(ii):line['id']})
		else:
			print(red("NO ACP FOUND"))					
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0	
	#print(acp_list)
	print()
	print(yellow("Step - 1 : OK DONE",bold=True))			
	print('====================================================================================')		
	acp=input("Into wich ACP you want to create this object ? : ")
	acp_id=acp_list[acp]
	print("ok acp_id = ",acp_id)
	
	print('====================================================================================')
	print(yellow(" Step 2 - Let's retreive all existing network object ids - mandatory for new security rule creation"))
	print ("getting network object groups IDs. Max objects to retrieve : limit = {}".format(limit))
	auth_token=new_auth_token[0]
	print("new token",auth_token)	
	net_objects_dict_ids={}
	net_objects_dict_types={}	
	api_url="/object/networkgroups"	
	offset=0
	go=1
	while go==1:	
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		#print(output)
		ii=0
		if objets.get('items'):
			for line in objets['items']:
				net_objects_dict_ids.update({line['name']:line['id']})
				net_objects_dict_types.update({line['name']:line['type']})	
				ii+=1	
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0		
	print ("getting single network objects IDs. Max objects to retrieve : limit = {}".format(limit))		
	auth_token=new_auth_token[0]
	print("token = ",auth_token)	
	
	api_url="/object/networkaddresses"	
	offset=0
	go=1
	while go==1:	
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		#print(output)
		ii=0
		if objets.get('items'):
			for line in objets['items']:
				net_objects_dict_ids.update({line['name']:line['id']})
				net_objects_dict_types.update({line['name']:line['type']})	
				ii+=1	
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0		
	print (yellow("OK DONE ( Step 2 )",bold=True))
	
	print('====================================================================================')
	print(yellow(" Step 3 - Let's retreive all existing Port object ids - mandatory for new security rule creation"))
	print ("getting port object groups IDs. Max objects to retrieve : limit = {}".format(limit))
	auth_token=new_auth_token[0]
	print("new token",auth_token)	
	port_objects_dict_ids={}
	port_objects_dict_types={}	
	api_url="/object/portobjectgroups"
	offset=0
	go=1
	while go==1:	
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		#print(output)
		ii=0
		if objets.get('items'):
			for line in objets['items']:
				port_objects_dict_ids.update({line['name']:line['id']})
				port_objects_dict_types.update({line['name']:line['type']})	
				ii+=1	
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0		
	print ("getting single port objects IDs. Max objects to retrieve : limit = {}".format(limit))		
	auth_token=new_auth_token[0]
	print("token = ",auth_token)	
	
	api_url="/object/ports"	
	offset=0
	go=1
	while go==1:	
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		#print(output)
		ii=0
		if objets.get('items'):
			for line in objets['items']:
				port_objects_dict_ids.update({line['name']:line['id']})
				port_objects_dict_types.update({line['name']:line['type']})	
				ii+=1	
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0		
	print (yellow("OK DONE ( Step 3 )",bold=True))
	
	print('===============================================================================================')
	print(yellow(" Step 4 - Create the Security Rule"))
	#create a accesspolicies	
	auth_token=new_auth_token[0]
	api_url="/policy/accesspolicies/"+acp_id+"/accessrules"		
	
	# create the source network directory 
	the_object_source_name="NEW_HOST-WEB_SERVER"
	the_object_source_name="any"
	the_object_source={}
	the_object_source.update({"name": the_object_source_name})
	the_object_source.update({"type": net_objects_dict_types[the_object_source_name]})
	the_object_source.update({"id": net_objects_dict_ids[the_object_source_name]})
	the_object_source_list=[]
	the_object_source_list.append(the_object_source)
	source={}
	source.update({"objects": the_object_source_list})
	
	#create the destination network directory
	the_object_dest_name="NEW_HOST-PATRICK_LAPTOP"
	the_object_dest={}
	the_object_dest.update({"name": the_object_dest_name})
	the_object_dest.update({"type": net_objects_dict_types[the_object_dest_name]})
	the_object_dest.update({"id": net_objects_dict_ids[the_object_dest_name]})
	the_object_dest_list=[]
	the_object_dest_list.append(the_object_dest)
	destination={}
	destination.update({"objects": the_object_dest_list})
	
	# create the destination port directory
	the_dest_port_object_name="FTP"
	the_port_object_dest={}
	the_port_object_dest.update({"name": the_dest_port_object_name})
	the_port_object_dest.update({"type": port_objects_dict_types[the_dest_port_object_name]})
	the_port_object_dest.update({"id": port_objects_dict_ids[the_dest_port_object_name]})
	the_port_object_dest_list=[]
	the_port_object_dest_list.append(the_port_object_dest)	
	port_destination={}
	port_destination.update({"objects": the_port_object_dest_list})	

	# Create JSON post_data to send to FMC
	post_data={}
	# example of post_data creation 1
	post_data = {	
	"action": "TRUST",
	"enabled": 1,
	"type": "AccessRule",
	"name": "TEST_RULE-2",
	"sourceNetworks": {
			"objects": [{
				"type": "NetworkGroup",
				"name": "any",
				"id": "69fa2a3a-4487-4e3c-816f-4098f684826e"
			}]
		}
	}
	
	# example of post_data creation 2 :  we add all relevant directories into the original post_data
	
	#post_data.update({"name": "Patrick_TEST_Rule"})
	#post_data.update({"enabled": True})
	#post_data.update({"action": "ALLOW"})
	#post_data.update({"type": "AccessRule"})
	#post_data.update({"description" : "My Description"})
	#post_data.update({"sourceNetworks": source})
	post_data.update({"destinationNetworks": destination})
	post_data.update({"destinationPorts": port_destination})
	
	#post_data.update({"logFiles": False})
	#post_data.update({"logBegin": False})
	#post_data.update({"logEnd": True})

	post_data=json.dumps(post_data,indent=4,sort_keys=True)
	
	print("Post Data :")
	print (post_data)
	auth_token=new_auth_token[0]
	fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,post_data)	
	print(green("OK ALL DONE. ACP {}".format(acp)))
