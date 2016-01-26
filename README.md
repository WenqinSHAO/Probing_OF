# Internet probing via multiple transit providers with OpenFlow-enabled networking
## Intro
This toy project is a demo using [OpenFlow](https://www.opennetworking.org/sdn-resources/openflow) to construct flexible routing tables required by the Internet probing task in a multi-homing environment,
where the path performance toward destination networks is measured via multiple transit providers that become available in this context.

## File description
- The network topology used in the demon is built with [mininet](http://mininet.org) using the *new_start.py* script, where,
  - *new_start.py* sets the interface IP address on hosts according to *IPCONFIG* and *PBR_TABLE*. 
More specifically, in *PBR_TABLE*, for each private IP source address used in probing, its transit next-hop and its type is given.
There are two types:
    1. PIP, for Provider IP, indicates that the traffic with this source IP should be NATed, when crossing the border, with provider interco IP so that returning traffic comes in via the same transit provider.
    2. CIP, for customer IP, indicates that the traffic with this source IP should be NATed with the provider independant IP of the local multiple-homed network, so that the returning traffic follows the same path as its normal data traffic in BGP routing.
  - *ROUTE* describes the default route needed on mininet hostes and is as well loaded by *new_start.py*.
- The OpenFlow controller in this demo bases on [Ryu](https://osrg.github.io/ryu/). 
The construction of OpenFlow pipeline is realised in *probing.py*. 
  - *probing.py* learns the network location, in format of dpid:port\_no, of each next hop in *NEXT_HOP*.
  - It learns as well the NAT and PBR (Policy Based Routing) tasks need to be performed in *PBR_TABLE*.
  - The OpenFlow switches are not aware of traditional networking stacks, yet hosts do, so do other hosts over the Internet. 
Therefore the OpenFlow controller have to bridge the difference by reading:
    * *VIR_IP* virtual IPs and MAC addresses meant to be assigned to OpenFlow switches;
    * *VIR_IP_INTF* the mapping relationship between virtual IP and OpenFlow switch interfaces. 
*gw* and *nat* are virtual interfaces instead of physical switch interfaces. 
They can be actually associated to arbitrary and multiple switch interfaces as long as local security policies not violated.
- *probing_mn_topo.png* illustrates the demo settings.
- *internet_probing_prez.pdf* presents the motivation and code structure of this toy project.

## Major advantage
As we can see from the above short description, the NAT and PBR operations needed to properly steer probing traffic are sort of tangled with each other,
that is traffic with certain private source IP need to be first properly NATed than forwarded, according to a source IP that is lost when NATing, to specific next-hop.
This task is not evident with traditional networking equipments or as least might require some tuning or obscure configurations to make it work.
However, with OpenFlow, communication and interaction of great liberty are made possible among different network function blocks, NAT and PBR in this case.
Further, our implementation showcased an approach to build multiple flow tables to form a pipeline of forwarding action, so that the OpenFlow flavour of networking is neatly and seamlessly incorporated into the traditional one.

