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

this script delete all network object with names contained in the output_network_objects.txt file
	
	
'''
import requests
import json
import yaml
import csv
import time
from pprint import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from pprint import pprint, pformat
from pathlib import Path
from crayons import blue, green, white, red, yellow,magenta, cyan

def yaml_load(filename):
	fh = open(filename, "r")
	yamlrawtext = fh.read()
	yamldata = yaml.load(yamlrawtext)
	return yamldata
	
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
	print (green("Token = "+auth_token))
	print(green("DOMAIN_UUID="+DOMAIN_UUID))
	print("Saved into token.txt file")

def delete_network_from_csv(host,port,token,UUID,version,file,username,password):
	'''
	Delete every items from the csv file
	'''
	headers = {'Content-Type': 'application/json'} 
	headers['X-auth-access-token']=token
	with open (file) as csvfile:
		entries = csv.reader(csvfile, delimiter=';')
		for row in entries:
			#print (' print the all row  : ' + row)
			#print ( ' print only some columuns in the rows  : '+row[1]+ ' -> ' + row[2] )	
			#print(row[0]+' : '+row[3]+'-'+row[3])
			if row[1]=='objects_group':
				object_type='portobjectgroups'
			else:
				object_type='protocolportobjects'
			try:
				request = requests.delete("https://{}:{}/api/fmc_config/v{}/domain/{}/object/{}/{}".format(host, port,version,UUID,object_type,row[3]), headers=headers, verify=False)		
				status_code = request.status_code
				resp = request.text
				print("Status code is: "+str(status_code))				
				if (status_code == 429):
					print(red("API is currently being rate-limited by FMC. Pausing for 60 seconds.",bold=True))
					time.sleep(60)
					request = requests.delete("https://{}:{}/api/fmc_config/v{}/domain/{}/object/{}/{}".format(host, port,version,UUID,object_type,row[3]), headers=headers, verify=False)
					status_code = request.status_code		
				if status_code == 401: 
					generate_fmc_token(host,port,username,password,version)	
					line_content = []
					with open('token.txt') as inputfile:
						for line in inputfile:
							if line.strip()!="":	
								line_content.append(line.strip())						
					auth_token = line_content[0]
					headers['X-auth-access-token']=auth_token			
					request = requests.delete("https://{}:{}/api/fmc_config/v{}/domain/{}/object/{}/{}".format(host, port,version,UUID,object_type,row[3]), headers=headers, verify=False)
					status_code = request.status_code
					
				if status_code == 200 or status_code == 201 or status_code == 202:
					print ("     Delete was successful...")
					#json_resp = json.loads(resp)
					#print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
				else :
					request.raise_for_status()
					print ("Error occurred in DELETE --> "+resp)				
				print(green("Object : {} - {} - {} Deleted".format(row[3],row[0],row[3]),bold=True))			
			except:
				raise
			#time.sleep(0.5)
	return (1)		


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
			
	print ('auth_token :',auth_token)
	print ('UUID : ',DOMAIN_UUID)
	print('======================================================================================================================================')	 
	api_url="/object/hosts"
	csvfile="output_service_objects.txt"
	print("DELETE SERVICE OBJECTS:")
	delete_network_from_csv(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,FMC_VERSION,csvfile,FMC_USER,FMC_PASSWORD)
	#print(json.dumps(networks,indent=4,sort_keys=True))
	print(green("ALL DONE"))
		   
	
	
