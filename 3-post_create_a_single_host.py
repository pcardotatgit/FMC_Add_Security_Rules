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
	This script creates single network objects
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

def fmc_post(host,port,token,UUID,url,version,post_data):
	url = "https://{}:{}/api/fmc_config/v{}/domain/{}{}".format(host, port,version,UUID,url)
	try:
	    # REST call with SSL verification turned off: 
	    r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
	    # REST call with SSL verification turned on:
	    # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
	    status_code = r.status_code
		print("Status code is (1): "+str(status_code))
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
			print("Let's ask for a new token")
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
	    print("Status code is: "+str(status_code))
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
			
	print ('auth_token :',auth_token)
	print ('UUID : ',DOMAIN_UUID)

	headers = {'Content-Type': 'application/json'} 
	headers['X-auth-access-token']=auth_token
	
	#create a host
	api_url="/object/hosts"
	post_data ={
	  "name": "PATTestHost",
	  "type": "Host",
	  "value": "20.20.20.20",
	  "description": "Test Description"
	}	
	fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,post_data)
	
	#create a fqdn
	api_url="/object/fqdns"
	post_data ={
  "name": "TestFQDN",
  "type": "FQDN",
  "value": "downloads.cisco.com",
  "dnsResolution": "IPV4_ONLY",
  "description": "Test Description"
}
	fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,post_data)		
	#create a network
	api_url="/object/networks"
	post_data =  {
    "name": "net1",
    "value": "1.0.0.0/24",
    "description": "Network obj 1",
    "type": "Network"
  }
	fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,post_data)	
  
	#create a range
	api_url="/object/ranges"
	post_data ={
  "name": "TestRange2",
  "value": "10.4.30.40-10.4.30.50",
  "type": "Range",
  "description": "Test Description"
}	
	fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,post_data)	
