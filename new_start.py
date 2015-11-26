#!/usr/bin/python

"""
Generating a simple topo for probing demo
prob node and remote server host are addressed and default route configured
"""

from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.util import quietRun
#from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE


IPCONFIG = './IPCONFIG'
PBR_TABLE = './PBR_TABLE'
ROUTE = './ROUTE'
IP_SETTING={}
ROUTE_SETTING={}

class B6Probing( Topo ):
    "B6 probing topo"
    
    def __init__( self, *args, **kwargs ):
        Topo.__init__( self, *args, **kwargs )
        bgp_router_1 = self.addSwitch('sw1', protocols='OpenFlow13', dpid='1')
        bgp_router_2 = self.addSwitch('sw2', protocols='OpenFlow13', dpid='2')
        local_as = self.addSwitch('sw3', protocols = 'OpenFlow13', dpid = '3')

        transit_1 = self.addHost('t1')
        transit_2 = self.addHost('t2')
        internet = self.addHost('internet')
        server = self.addHost('server')
        probe = self.addHost('probe')

        self.addLink(probe, local_as)
        self.addLink(local_as, bgp_router_1)
        self.addLink(local_as, bgp_router_2)
        self.addLink(bgp_router_1, transit_1, delay='0ms')
        self.addLink(bgp_router_1, transit_2, delay='50ms')
        self.addLink(bgp_router_2, transit_1, delay='20ms')
        self.addLink(bgp_router_2, transit_2, delay='100ms')
        self.addLink(transit_1, internet)
        self.addLink(transit_2, internet)
        self.addLink(internet, server)

def get_ip_setting():
    if (not os.path.isfile(IPCONFIG)):
        return -1
    f = open(IPCONFIG, 'r')
    for line in f:
        name, ip = line.split()
        print name, ip
        IP_SETTING[name] = ip
    return 0

def get_route_setting():
    if (not os.path.isfile(ROUTE)):
        return -1
    f = open(ROUTE, 'r')
    for line in f:
        node, entry = line.split()
        ROUTE_SETTING[node]=entry
    return 0
   
def set_probing_ip(host):
    info ('*** setting probing source IP for %s\n' % host.name)
    if (not os.path.isfile(PBR_TABLE)):
        info("DEBUG: PBR file doesn't exist.")
        return 
    f = open(PBR_TABLE, 'r')
    i=1
    for line in f:
        ip = line.split()[0]
        host.cmd('ifconfig lo:%s %s' %(i, ip))
        i+=1

def host_node_ifconfig(host):
    info('*** setting IP and default gateway for %s\n' % host.name)
    if(host.name == 'probe'):
        gw_ip = IP_SETTING['vir_gw']
    elif(host.name == 'server'):
        gw_ip = IP_SETTING['internet-eth2']
    info(host.name, 'ip:', IP_SETTING[host.name], 'gw:', gw_ip, '\n')
    #setting IP address
    intf = host.defaultIntf()
    intf.setIP('%s' % IP_SETTING[host.name])
    #setting default gateway
    host.cmd('ip route add default via %s' % gw_ip.split('/')[0])
    #host.cmd('ip route add default %s' % gw_ip)
    #host.cmd('route add %s/32 dev %s-eth0' % (gw_ip, host.name))
    #host.cmd('route add default gw %s dev %s-eth0' % (gw_ip, host.name))
    #HARDCODED
    #host.cmd('route del -net 10.3.0.0/16 dev %s-eth0' % host.name)
    #del routes given with default config
    #ips = IP_SETTING[host.name].split(".") 
    #host.cmd('route del -net 10.0.0.0/8 dev %s-eth0' % host.name)

def network_node_ifconfig(node):
    info('*** setting IP and routes for %s\n' % node.name)
    node.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
    node.cmd('echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter')
    node.cmd('echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter')
    node.cmd('echo 0 > /proc/sys/net/ipv4/conf/lo/rp_filter')
    for intf in IP_SETTING:
        if node.name in intf:
            ip, prefix = IP_SETTING[intf].split('/')
            node.setIP(ip, prefix, intf)
            node.cmd('echo 0 > /proc/sys/net/ipv4/conf/%s/rp_filter' % intf)
            info(intf, IP_SETTING[intf], '\n')
    for nd in ROUTE_SETTING:
        if node.name in nd:
            routes = ROUTE_SETTING[nd].split(';')
            for route in routes:
                prefix, nh = route.split('-')
                node.cmd('ip route add %s via %s' % (prefix, nh))
                info(prefix, 'via', nh, '\n') 
       

def start_web_server(host):
    info( '*** Starting SimpleHTTPServer on ', host, '\n' )
    host.cmd( 'cd ~/web_b6; nohup python -m SimpleHTTPServer 80 &')

def stop_web_server(host):
    info( '*** Shutting down stale SimpleHTTPServers', 
          quietRun( "pkill -9 -f SimpleHTTPServer" ), '\n' ) 

def probnet_building():   
    #read ./IP_CONFIG config file for host addressing
    r = get_ip_setting()
    if r == -1:
        exit("Couldn't load config file for ip addresses, check whether %s exists" % IPCONFIG_FILE)
    else:
        info( '*** Successfully loaded ip settings\n %s\n' % IP_SETTING)
    get_route_setting()
    topo = B6Probing()
    info( '*** Creating network\n' )
    net = Mininet( topo=topo, controller=RemoteController, link=TCLink)
    net.start()
    
    #get node objects
    probe, server, internet, transit_1, transit_2 = net.get( 'probe', 
                                                             'server',
                                                             'internet',
                                                             't1',
                                                             't2')

    #set IP address and default routes to prob and server nodes
    #it's quite ugly this part of code, try to rewrite
    host_node_ifconfig(probe)
    host_node_ifconfig(server)
    network_node_ifconfig(internet)
    network_node_ifconfig(transit_1)
    network_node_ifconfig(transit_2)
    set_probing_ip(probe)
    start_web_server( server )
    CLI( net )
    stop_web_server( server )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    probnet_building()

