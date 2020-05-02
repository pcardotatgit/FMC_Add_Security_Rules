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

This script	displays and save into network_objects.txt file all network objects 
except  any-ipv4 and any-ipv6

'''
import requests
import json
import yaml
from pprint import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from pprint import pprint, pformat
from pathlib import Path
from crayons import blue, green, white, red, yellow,magenta, cyan

limit=10000 # number of object to retreive in one object request
new_auth_token=[]#as global variable in order to make it easily updatable 
new_auth_token.append("zzz") 

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
		print("Status code is: "+str(status_code))
		if status_code == 401: 
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

if __name__ == "__main__":
	FMC_Server = {}
	FMC_Server = yaml_load("FMC_profile.yml")
	print()
	print(yellow("Get All Network Objects  :", bold=True))
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
	print('================================================================================================')	
	fa = open("output_network_objects.txt","w")  
	go=1
	offset=0
	
	while go==1:			
		# List Network Groups
		api_url="/object/networkgroups"
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		# save json output
		#output=json.dumps(objets,indent=4,sort_keys=True)
		#print(output)
		#fa.write(output)
		if objets.get('items'):	
			ii=0
			for line in objets['items']:
				ii+=1
				if line['metadata'].get('readOnly'):
					print(red('THIS IS A SYSTEM OBJECT'))					
				else:			
					print('name:', line['name'])
					#print(line['objects'])
					#for line2 in line['objects']:		
					#	print('==',line2['name'])
					print('description:', line['description'])
					print('type:', line['type'])
					print('id:', line['id'])
					print()		
					condition=1
					#check here for a condition to save result				
					if condition==1:
						fa.write(line['name'])
						fa.write(';')
						fa.write(' OBJECT LIST')				
						fa.write(';')   
						if line['description']==None:
							line['description']="No Description"
						fa.write(line['description'])
						fa.write(';')			
						fa.write(line['type'])
						fa.write(';')
						fa.write(line['id'])
						fa.write('\n')
		else:
			print(red("NO NETWORK GROUPS FOUND"))
			
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0					
	offset=0	
	go=1
	while go==1:
		# List Network Addesses Objects ( host and ip addresses and ranges )
		auth_token=new_auth_token[0]
		api_url="/object/networkaddresses"
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		# save json output
		#output=json.dumps(objets,indent=4,sort_keys=True)
		#print(output)
		#fa.write(output)	
		if objets.get('items'):
			ii=0
			for line in objets['items']:
				ii+=1
				if line['metadata'].get('readOnly'):
					if line['metadata']['readOnly'].get('reason'):
						print(red('THIS IS A SYSTEM OBJECT'))					
				else:				
					print('name:', line['name'])
					print('value:', line['value'])
					print('description:', line['description'])
					print('type:', line['type'])
					print('id:', line['id'])
					print('Nb:', str(ii))
					print()		
					condition=1
					#check here for a condition to save result
					if "N_range" not in line['name']:
						condition=0
					condition=1
					if condition==1:
						fa.write(line['name'])
						fa.write(';')			
						fa.write(line['value'])
						fa.write(';')   
						if line['description']==None:
							line['description']="No Description"
						fa.write(line['description'])
						fa.write(';')			
						fa.write(line['type'])
						fa.write(';')
						fa.write(line['id'])
						fa.write('\n')	
		else:
			print(red("NO NETWORK GROUPS FOUND"))					
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0
	
	fa.close()	
	print('================================================================================================')		
	print(cyan("ALL DONE . The result is in output_network_objects.txt file",bold=True))
	
	
