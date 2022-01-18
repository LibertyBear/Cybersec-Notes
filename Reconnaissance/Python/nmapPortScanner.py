import nmap
import sys
import pprint
import pprint 


nm_scan = nmap.PortScanner() #scanner object
#nm_scanner = nm_scan.scan('127.0.0.1', '21-443')
nm_scanner = nm_scan.scan(sys.argv[1], '80', arguments='-O')
pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(nm_scanner)


print("The host is " + nm_scanner['scan'][sys.argv[1]]['status']['state']) #is up/down

print("The port 80 is " + nm_scanner['scan'][sys.argv[1]]['tcp'][80]['state']) #is open/closed

print("The scanning method is " + nm_scanner['scan'][sys.argv[1]]['tcp'][80]['reason']) #scan method


a = " "
b = " "
a = nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['accuracy']
b = nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['name']


print("There is ", a,  " chance the host is running ", b)

