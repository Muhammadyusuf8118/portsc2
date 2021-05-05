
#!/usr/bin/python

from socket import *
import optparse
from threading import *

def Scan(tgtHost, tgtPort):
	try:
		sock = socket(AF_INET, SOCK_STREAM)
		sock.connect((tgtHost, tgtPort))
		print '[*] ' + str(tgtPort) + " /tcp porti ochiq!  "
	except:
		print '[*] ' + str(tgtPort) + " /tcp porti yopiq!  "

	finally:
		sock.close()

def portscaner(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print '[*]' + tgtHost + '.ning ip adresi topilmadi! '
	try:
		tgtName = gethostbyaddr(tgtIP)
		print '[*]' + tgtName[0] + ' uchun Scaner Natijalari: '
	except:
		print '[*]' + tgtIP + ' uchun Scaner Naijalari: '
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target = Scan, args= (tgtHost, int(tgtPort)) )
		t.start()



def main():

	parser = optparse.OptionParser("Programmadan foydalanish texnikasi:-->"+ "--H <Nishon IP> --p <Nishon Porti>")
	parser.add_option('--H', dest='tgtHost', type ='string', help='IP addresni aniqlashtiring')
	parser.add_option('--p', dest='tgtPort', type ='string', help='Nishon portini aniqlashtiring')
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPorts = str(options.tgtPort).split(',')
	if (tgtHost ==None) | (tgtPorts[0] == None):
		print parser.usage
		exit()
	else:
		portscaner(tgtHost, tgtPorts)

if __name__=='__main__': 
	main()
