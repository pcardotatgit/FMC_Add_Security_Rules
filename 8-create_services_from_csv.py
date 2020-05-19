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
	This script add all service objects from the service_objects.csv file

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
import time

csv_file_to_read= "service_objects.csv"
max_objects=500 #max number of object to send to FMC in a single POST Call
new_auth_token=[]#as global variable in order to make it easily updatable 
new_auth_token.append("zzz") 
existing_name_list=[] # List of existing names into FMC 
limit=1100 #number of object to retrieve from FMC in a single GET cal
go_create_object=1 # for debuggin 1=send new object to FMC  0=dont

# Locate the directory containing this file and the repository root.
# Temporarily add these directories to the system path so that we can import
# local files.
here = Path(__file__).parent.absolute()
repository_root = (here / "./files" ).resolve()
sys.path.insert(0, str(repository_root))

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
		
def fmc_post(host,port,token,UUID,url,version,post_data,username,password):
	url = "https://{}:{}/api/fmc_config/v{}/domain/{}{}".format(host, port,version,UUID,url)
	headers['X-auth-access-token']=token
	try:
		# REST call with SSL verification turned off: 
		r = requests.post(url, data=json.dumps(post_data), headers=headers, verify=False)
		# REST call with SSL verification turned on:
		# r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
		status_code = r.status_code		
		print("Status code is (2): "+str(status_code))
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
		
	
def read_csv(file):
	'''
	read csv file and generate  JSON Data to send to FMC Server
	'''
	objects=[]
	fqdns=[]
	ranges=[]
	networks=[]
	with open (file) as csvfile:
		entries = csv.reader(csvfile, delimiter=';')
		for row in entries:
			#print (' print the all row  : ' + row)				
			row[0]=row[0].strip()
			if row[0] not in existing_name_list:	
				print ( ' ADD  : '+row[0]+ ' -> ' + row[3] )
				row[1]=row[1].lower()
				if row[1]=='object' or row[1]=='range':
					payload = {
						"name":row[0],
						"description":row[4],
						"type":"ProtocolPortObject",
						"port":row[3],
						"protocol":row[2]
					}					
					objects.append(payload)
			else:
				print(red("Read CSV => Object [  {}   ] already exists in FMC we dont add it ".format(row[0]),bold=True))
				aa=1
	#print(objects)
	return (objects)
	
if __name__ == "__main__":
	FMC_Server = {}
	FMC_Server = yaml_load("FMC_profile.yml")
	print(yellow("Get system information of FMC Server  :", bold=True))
	print()	
	pprint(FMC_Server["FMC_Server"])	
	#pprint(FMC_Server["FMC_Server"][0]['ipaddr'])
	FMC_USER = FMC_Server["FMC_Server"][0]['username']
	FMC_PASSWORD = FMC_Server["FMC_Server"][0]['password']
	FMC_IPADDR = FMC_Server["FMC_Server"][0]['ipaddr']
	FMC_PORT = FMC_Server["FMC_Server"][0]['port']
	FMC_VERSION = FMC_Server["FMC_Server"][0]['version']
	print()
	server = "https://"+FMC_IPADDR+':'+str(FMC_PORT)
	fh = open("error.log", "w")
	fh.close() 
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
	
	print('======================================================================================================================================')	
	print (yellow("Step 1 - first let's retreive all existing object names in order to avoid conflicts during object creation"))
	# List Network Groups
	print ("getting service object groups. Max objects to retrieve : limit = {}".format(limit))
	api_url="/object/portobjectgroups"
	offset=0
	go=1
	while go==1:	
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		ii=0
		if objets.get('items'):
			for line in objets['items']:
				existing_name_list.append(line['name'])	
				ii+=1				
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0	
	print ("getting single service objects. Max objects to retrieve : limit = {}".format(limit))
	auth_token=new_auth_token[0]
	print("1",auth_token)
	api_url="/object/ports"
	offset=0
	go=1
	while go==1:	
		objets = fmc_get(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,FMC_USER,FMC_PASSWORD,offset)
		ii=0
		for line in objets['items']:
			existing_name_list.append(line['name'])	
			ii+=1	
		if ii>=999:
			go=1
			offset+=ii-1
		else:
			go=0
	fi = open("existing_service_objects.txt", "w")	
	for nom in 	existing_name_list:	
		fi.write(nom)
		fi.write("\n")			
	fi.close()				
	print (yellow("OK DONE ( Step 1 )list saved the existing_service_objects.txt file",bold=True))
	print('======================================================================================================================================')	
	print (yellow("Step 2 - let's read the {} file and add all new service objects to the object list to send to FMC".format(csv_file_to_read),bold=True))
	csv_file_to_read= repository_root / csv_file_to_read
	#ctr_report_path = here / f"ctr_report_{report_time}.json"
	print("csv file to read =",csv_file_to_read)
	objects_list={}
	objects_list=read_csv(csv_file_to_read)
	#print(objects_list)
	print (yellow("OK DONE ( Step 2 )",bold=True))
	print('======================================================================================================================================')	
	if go_create_object==1:
		auth_token=new_auth_token[0]
		print("2 token =",auth_token)
		print (yellow("Step 3 : go_create_object=1 then Let's send object to FMC",bold=True))
		print ("   Number of objects to create in one single Rest call : max_objects = {}".format(max_objects))
		if not objects_list:
			print(red("NO SERVICE OBJECTS TO SEND TO DEVICE",bold=True))
		else:
			print(green("WE HAVE SOME SERVICE OBJECTS TO SEND TO DEVICE. Let's do it",bold=True))
			api_url="/object/protocolportobjects?bulk=true"
			i=0
			sent_objects_list=[]
			for objet in objects_list:
				print (objet)
				sent_objects_list.append(objet)
				if i==max_objects:
					print(yellow("SEND SINGLE SERVICES TO DEVICE (1)",bold=True))
					fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,sent_objects_list,FMC_USER,FMC_PASSWORD )
					i=0
					sent_objects_list.clear()
				i+=1		
			if i<max_objects-1:
				print(yellow("SEND SINGLE SERVICES TO DEVICE (2)",bold=True))
				fmc_post(FMC_IPADDR,FMC_PORT,auth_token,DOMAIN_UUID,api_url,FMC_VERSION,sent_objects_list,FMC_USER,FMC_PASSWORD )
			else:
				print(red("STOP HERE",bold=True))
		print('======================================================================================================================================')	
	else:
		print("We have skipped the object creation go_create_object=0")
		print (yellow("Step 3 : go_create_object=0 then we skip sending object to FMC",bold=True))
		#for nom in existing_name_list:
		#	print(nom)
		
		for nom in objects_list:
			print(json.dumps(nom,sort_keys=True,indent=4, separators=(',', ': ')))			
	print(green("OK ALL DONE",bold=True))