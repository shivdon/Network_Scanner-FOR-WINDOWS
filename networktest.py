import scapy.all as scapy

import optparse

import socket 

import os

import re



def getArguments():

	parser = optparse.OptionParser()

	parser.add_option("-t", "--target", dest="target", help="Target IP / IP range")

	(options, arguments) = parser.parse_args()

	

	return options	



def scan(ip):

#   creating arp request for sending/asking the networks who has the ip sent 

    arp_request = scapy.ARP(pdst=ip)



#   broadcast is required to send the ar request via mac address for the networks

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    

    broadcast_arp_request = broadcast/arp_request

    answered_list = scapy.srp(broadcast_arp_request, timeout = 1, verbose=False)[0]



#   response stored in answered in the form of lists according to documentation

    #print(answered.summary())



    client_list = []

    

    for answer in answered_list:

#       fetching ip and mac of the target

        client_dict = {"ip" : answer[1].psrc, "mac":answer[1].hwsrc}

        client_list.append(client_dict)

    

    return client_list

    

       

    

    

 

def print_result(result_list):  

    print("IP\t\t\tMAC ADDRESS")

    print("***************************************************\n")  

    for output in result_list:

	    print(output["ip"], "\t\t", output["mac"], "\n-------------------------------------------------")     	

		

option = getArguments()

	

scanned_result = scan(str(option.target))



print_result(scanned_result)