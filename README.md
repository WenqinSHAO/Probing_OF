# Probing_OF
This toy project is a demo using [OpenFlow](https://www.opennetworking.org/sdn-resources/openflow) to construct flexible routing tables required by the Internet probing task in a multi-homing environment.
The path performance toward destination networks is measured via multiple transit providers that become available in this context.

The network topology used in the demon is built with [mininet](http://mininet.org) using the *new_start.py* script.
The OpenFlow controller bases on [Ryu](https://osrg.github.io/ryu/). 
The construction of OpenFlow pipeline is realised in *probing.py*. 
The major advantage of using OpenFlow achieving such a task is that is allows the highly liberal communication and interaction among different network function blocks, NAT and PBR (Policy Based Routing) in this case.
In this repository, a figure, *probing_mn_topo.png*, illustrating the demo settings and slides ,*internet_probing_prez.pdf*, presenting the motivation and code structure of this toy project can as well be found.
