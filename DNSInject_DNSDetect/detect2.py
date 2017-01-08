import sys, getopt
from collections import deque
from scapy.all import *
import re
pkt_queue = deque(maxlen = 100) # a queue for incoming packets
txid = deque(maxlen =1000)# a queue to handle transaction IDs

def handle_packet(pkt):
    if pkt.haslayer(DNS) :
        if len(pkt_queue) > 0:
            for old_pkt in pkt_queue:
		if old_pkt.haslayer(DNS) and\
                old_pkt[DNS].id== pkt[DNS].id  and  pkt.getlayer(DNS).an is not None and\
                old_pkt.getlayer(DNS).an is not None and old_pkt.getlayer(DNS).an != pkt.getlayer(DNS).an :
			#print 'spoofed packet loop'
			#pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
			#test = pat.match(old_pkt.getlayer(DNS).an.rdata)
			#test1 = pat.match(pkt.getlayer(DNS).an.rdata)
                        #if test and test1 :
			# The below condition takes care of duplicate DNS records
			if pkt[DNS].id not in txid:
					print 'DNS Poisioning Attack --- DETECTED  --------> spoofed packet'
    			        	print 'TXID', pkt[DNS].id,' Request', old_pkt.getlayer(DNS).an.rrname
					printIPaddress(old_pkt.getlayer(DNS).an)
					printIPaddress(pkt.getlayer(DNS).an)
			txid.append(pkt[DNS].id)	
			#pkt.show()
        pkt_queue.append(pkt)
# It ensures that the address printed is IP and not canonical name
def printIPaddress(pkt):
	if pkt.payload.name == "NoPayload":
		print pkt.rdata
	while pkt.payload.name != "NoPayload":
		if pkt.payload.type == 1:
			print pkt.payload.rdata
		pkt = pkt.payload

def main(argv):
    interface = ''
    filename = ''
    expression = ''
    
    try:
        opts, args = getopt.getopt(argv, 'i:r::')
    except getopt.GetoptError:
        print 'use -i <interface> <optional expression>'
        print '   or:-r <filename> <optional expression>'
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-i':
            interface = arg
        elif opt == '-r':
            filename = arg
    
    if len(args) == 1:
        expression = args[0]
    elif len(args) > 1:
        print '\n\tExceeded the Maximum number of arguments!\n'
        sys.exit()
    
    print '\n\tInitializing DNSDetect parameters using following parameters:\n',\
        '\t\tinterface:', interface, '\n',\
        '\t\tPcap file:', filename, '\n',\
        '\t\texpression:', expression, '\n'
    
    if interface != '' and filename != '':
        print 'Please only use interface OR file name!\n'
        sys.exit()
    elif interface == '' and filename == '':
        print '\tSniffing on all interfaces by default'
        sniff(prn = handle_packet, filter = expression)
    elif interface != '' and filename == '':
        print '\tSniffing on interface', interface
        sniff(iface = interface, prn = handle_packet, filter = expression)
    else:
        print '\tSniffing offline trace file', filename
        sniff(offline = filename, prn = handle_packet, filter = expression)

if __name__ == "__main__":
    main(sys.argv[1:])
