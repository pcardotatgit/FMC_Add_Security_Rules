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

what is it :

	This script add all service objects groups from the service_object_groups.csv file

'''
import sys
import csv
import requests
import yaml
import json
from pprint import pprint
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from pprint import pprint, pformat
from pathlib import Path
from crayons import blue, green, white, red, yellow,magenta, cyan

max_objects=500

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

def fmc_get(host,port,token,UUID,url,version,username,password):
	'''
	This is a GET request to obtain the list of all Network Objects in the system.
	'''
	headers = {
		"Content-Type": "application/json",
		"Accept": "application/json",
		"X-auth-access-token":"{}".format(token)
	}

	try:
		request = requests.get("https://{}:{}/api/fmc_config/v{}/domain/{}{}?expanded=true&limit=100".format(host, port,version,UUID,url),verify=False, headers=headers)
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
			request = requests.get("https://{}:{}/api/fmc_config/v{}/domain/{}{}?expanded=true&limit=100".format(host, port,version,UUID,url),verify=False, headers=headers)
			status_code = request.status_code
		resp = request.text
		if status_code == 200 or status_code == 201 or status_code == 202:
			print ('OK')
		return request.json()
	except:
		raise	
	
def fmc_post(host,port,token,UUID,url,version,post_data,username,password):
	url = "https://{}:{}/api/fmc_config/v{}/domain/{}{}?bulk=true".format(host, port,version,UUID,url)
	try:
		# REST call with SSL verification turned off: 
		r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
		# REST call with SSL verification turned on:
		# r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
		status_code = r.status_code		
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
			r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
			status_code = r.status_code
		resp = r.text
		if status_code == 201 or status_code == 202:
			print (green("Post was successful...",bold=True))
			json_resp = json.loads(resp)
			#print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
		else :
			r.raise_for_status()
			print ("Error occurred in POST --> "+resp)
	except requests.exceptions.HTTPError as err:
		print ("Error in connection --> "+str(err))
	finally:
		if r: r.close()
		
	
def read_csv(file,net_objects_dict_ids,net_objects_dict_types):
	'''
	read csv file and generate  JSON Data to send to FMC Server
	'''
	donnees=[]
	with open (file) as csvfile:
		entries = csv.reader(csvfile, delimiter=';')
		for row in entries:
			#print (' print the all row  : ' + row)
			#print ( ' print only some columuns in the rows  : '+row[1]+ ' -> ' + row[2] )	
			row[1]=row[1].lower()
			payload = {}
			payload.update({"name":row[0]})
			payload.update({"description":row[3]})
			objets=[]	
			liste_objets=[]
			liste_objets=row[2].split(',')
			for objet in liste_objets:		
				the_objet={}
				the_objet.update({"id": net_objects_dict_ids[objet]})
				the_objet.update({"type":net_objects_dict_types[objet]})
				objets.append(the_objet)
			payload.update({"objects": objets})
			payload.update({"type": "NetworkGroup"})			
			donnees.append(payload)
	#print(objects)
	return (donnees)
	
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
	print('======================================================================================================================================')	
	# First get all single object ids
	api_url="/object/ports"
	objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD)	
	#print(objets)
	net_objects_dict_ids={}
	net_objects_dict_types={}
	for line in objets['items']:
		net_objects_dict_ids.update({line['name']:line['id']})
		net_objects_dict_types.update({line['name']:line['type']})
	#print(net_objects_dict_ids)	
	#print(net_objects_dict_ids['AGENCE-LYOG-CLUST_addresses'])
	#print(net_objects_dict_types['LAN_INTERNET_ORANGE'])
	objects_list={}
	objects_list=read_csv("service_object_groups.csv",net_objects_dict_ids,net_objects_dict_types)	
	#(json.dumps(objects_list,sort_keys=True,indent=4, separators=(',', ': ')))
	api_url="/object/portobjectgroups"
	fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,objects_list,FMC_USER,FMC_PASSWORD)
	#print(objects_list)
	print('======================================================================================================================================')		

	print(green("OK ALL DONE",bold=True))