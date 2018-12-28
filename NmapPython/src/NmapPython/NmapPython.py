'''
Created on Oct 28, 2018

@author: groot
'''

import nmap
import optparse
import socket

def nmapScan(tgtHost, tgtPort):
    nmScan=nmap.PortScanner()
    tgtHost_ip= socket.gethostbyname(tgtHost)#'10.166.26.26'
    nmScan.scan(tgtHost,tgtPort)
    state=nmScan[tgtHost_ip]['tcp'][int(tgtPort)]['state']
    print("[*] "+tgtHost+" tcp/"+tgtPort+" "+state)

def main():
    parser = optparse.OptionParser('usage%prog -H <target_host> -p <target_port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPorts', type='string', help='specify target port[s] separated by comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPorts).split(',')
    if (tgtHost == None) | (tgtPorts[0] == None):
        print (parser.usage)
        exit(0)
    for tgtPort in tgtPorts:
        nmapScan(tgtHost, tgtPort)

if __name__ == '__main__':
    main()