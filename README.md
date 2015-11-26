# Probing_OF
This toy project is a demo using OpenFlow constructing flexibale routing tables required in Internet probing via multiple transit provider in a multi-homing environment.
The network topology used in the demon is built with mininet using the new_start.py script.
The OpenFlow controller bases on Ryu, and the controller logic is given in probing.py, where how the OF pipline is built is described.
The major advantage of using OpenFlow achieving such a task is that is allows the coomunication among different network function blocks, NAT and PBR in this case.
In this repository, a figure illustrating the demo setting and slides presenting the motivation and code structure can be found.
