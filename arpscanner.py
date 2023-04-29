'''
ARP Scanner 

Author: (github.com/cpu0x00)
'''

import scapy.all as scapy 
from mac_vendor_lookup import MacLookup
import argparse
import colorama

parser = argparse.ArgumentParser(epilog='asset discovery using ARP')

parser.add_argument('target', help='the target network subnet for asset discovery [EX: 10.10.10.0/24]')
parser.add_argument('--spoof', '-s',help='an ipv4 address to spoof the connections with')
parser.add_argument('--tries', '-r', type=int, default=2, help='how many time to re-scan (the higher the more reliable) default=2')

args = parser.parse_args()

discoverd = []

elements = []

def arping(target):
	print(f"[*] arping {target}")
	
	if args.spoof:
		print(f'{colorama.Fore.BLUE}[*] spoofing all arp requests as: {args.spoof}{colorama.Style.RESET_ALL}')
		arp_p = scapy.ARP(pdst=target, psrc=args.spoof)
	if not args.spoof:
		arp_p = scapy.ARP(pdst=target)
	
	broadcast_p = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_broadcast_p = broadcast_p/arp_p

	for i in range(args.tries):
		print(f'\npacket transmission {i+1}:', end=' ')
		element_list, unans = scapy.srp(arp_broadcast_p, timeout=2, verbose=False)
		print(f'{colorama.Fore.BLUE}recieved {len(element_list)} response(s),{colorama.Style.RESET_ALL}', end=' ')
		print(f'{colorama.Fore.RED}{len(unans)} unanswered requests{colorama.Style.RESET_ALL}')
		elements.append(element_list)

	def mac_lookup(mac):
		try:
			vendor = MacLookup().lookup(mac)
			if vendor:
				return vendor	
			else: return ''
		except Exception as e:
			pass

	for lst in elements:
		for element in lst:

			discoverd.append(f''' 
{element[1].psrc}  {element[1].hwsrc}  {mac_lookup(element[1].hwsrc)}''')

	print('\n---------------------------------------------')
	print("Assets:\n")
	print(''.join(set(discoverd)))

	
arping(args.target)