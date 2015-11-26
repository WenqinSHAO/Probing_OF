from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, icmp, tcp
from ryu.ofproto import ether, inet
from netaddr import IPAddress, IPNetwork
from random import randint
import os.path

PJT_DIR = '/home/b6/b6_probing/'
PBR_TABLE = 'PBR_TABLE'
NEXT_HOP = 'NEXT_HOP'
VIRTUAL_IP = 'VIR_IP'
VIRTUAL_IP_INTF = 'VIR_IP_INTF'

class B6NatPbr(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(B6NatPbr, self).__init__(*args, **kwargs)
        self.next_hop =  self.load_config(NEXT_HOP) # 'ip':'dpid:port_no'read from NEXT_HOP
        self.mac_table = {} # 'ip':'mac' 
        self.probe_conf = self.load_config(PBR_TABLE) # 'src_ip':'type@nexthop' read from PBR_TABLE
        self.virtual_ip = self.load_config(VIRTUAL_IP) # 'ip':'mac' read from VIR_IP
        self.virtual_ip_intf = self.load_config(VIRTUAL_IP_INTF) # 'ip':'dpid:port_no' read from VIR_IP_INTF
        self.nat_ip = '' 
        self.nat_tcp_in2out = {} #'ip:port':'ip:port'
        self.nat_tcp_out2in = {}
        self.used_port = {}
        self.nat_icmp_in2out = {} #'ip:id':'ip:id'
        self.nat_icmp_out2in = {}
        self.used_id = {}

    @staticmethod
    def load_config(conf):
        conf_dict = {}
        conf_file = PJT_DIR + conf
        if (not os.path.isfile(conf_file)):
            return conf_dict
        else:
            f = open(conf_file, 'r')
            for line in f:
                key, entry = line.split()
                conf_dict[key] = entry
        return conf_dict
    
    def _arp_handler(self, datapath, in_port, pkt):
        eth_hd = pkt.get_protocol(ethernet.ethernet)
        arp_hd = pkt.get_protocol(arp.arp)
        
        #if not ((arp_hd.src_ip in self.mac_table) and (self.mac_table[arp_hd.src_ip]==arp_hd.src_mac)):
        if True:
            self.mac_table[arp_hd.src_ip] = arp_hd.src_mac
            print('INFO: MAC learnt %s@%s at dpid %s' % (arp_hd.src_ip, arp_hd.src_mac, str(datapath.id)))
            #install flows in mac table
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            actions = [parser.OFPActionSetField(eth_dst=arp_hd.src_mac)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)]
            if datapath.id == 3:
                #if arp_hd.src_ip == '192.168.0.2':
                    #for ip in self.probe_conf:
                        #match = parser.OFPMatch(eth_type=0x800,
                                                #ipv4_dst=ip)
                        #actions = [parser.OFPActionSetField(eth_dst=arp_hd.src_mac)]
                        #inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions)]
                        #self._add_flow(datapath, 3, 10, 0, match, inst)
                match = parser.OFPMatch(eth_type=0x800,
                                        ipv4_dst=arp_hd.src_ip)
                self._add_flow(datapath, 3, 10, 0, match, inst)
            else:
                match = parser.OFPMatch(metadata=int(IPAddress(arp_hd.src_ip)))
                self._add_flow(datapath, 4, 10, 0, match, inst)
                
        #reply arp request       
        if arp_hd.opcode == arp.ARP_REQUEST and arp_hd.dst_ip in self.virtual_ip:
            arp_reply = packet.Packet()
            arp_reply.add_protocol(ethernet.ethernet(ethertype=eth_hd.ethertype,
                                                     dst=eth_hd.src,
                                                     src=self.virtual_ip[arp_hd.dst_ip]))
            arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                           src_mac=self.virtual_ip[arp_hd.dst_ip],
                                           src_ip=arp_hd.dst_ip,
                                           dst_mac=arp_hd.src_mac,
                                           dst_ip=arp_hd.src_ip))
            self._send_packet_port(datapath, in_port, arp_reply)

    def _arp_request(self, datapath, in_port, pkt):
        ipv4_hd = pkt.get_protocol(ipv4.ipv4)
        print ('INFO: mac table miss: ip_src: %s -> ip_dst: %s at dpid %s' % (ipv4_hd.src, ipv4_hd.dst, str(datapath.id)))
        nh, port = self._find_nh(datapath, ipv4_hd.src, ipv4_hd.dst)
        vir_ip = self._find_vip_from_nh(nh)
        print('INFO: send arp request for %s from dpid %s via port %s using %s' % (nh, str(datapath.id), str(port), vir_ip))
        arp_request = packet.Packet()
        arp_request.add_protocol(ethernet.ethernet(ethertype=ether.ETH_TYPE_ARP,
                                                   dst='ff:ff:ff:ff:ff:ff',
                                                   src=self.virtual_ip[vir_ip]))
        arp_request.add_protocol(arp.arp(opcode=arp.ARP_REQUEST,
                                         src_mac=self.virtual_ip[vir_ip],
                                         src_ip=vir_ip,
                                         dst_mac='00:00:00:00:00:00',
                                         dst_ip=nh))
        self._send_packet_port(datapath, int(port), arp_request)

    def _find_nh(self, datapath, ip_src, ip_dst):
        #given ip_src and ip_dst, find the nh
        #quite stupid doing so because metadata can't be passed to controller        
        nh = ''
        if datapath.id == 1 or datapath.id == 2:
            #probe
            if ip_src in self.probe_conf:
                nh = self.probe_conf[ip_src].split('@')[1]
            #dst in nh
            elif ip_dst in self.next_hop:
                nh = ip_dst
            #default out, port 2 on dp 1 and dp 2 is the default out
            else:
                for ip in self.next_hop:
                    dpid, port = self.next_hop[ip].split(':')
                    if dpid == str(datapath.id) and int(port) == 2:
                        nh = ip
                        break
            port = int(self.next_hop[nh].split(':')[1])
            return (nh, port)
        elif datapath.id == 3:
            if IPAddress(ip_dst) in IPNetwork('192.168.0.0/24'):
                return (ip_dst, 1)
            else:
                return (ip_dst, 1)

    def _find_vip_from_nh(self, nh):
        #find the virtual ip with with we can send arp request with to the nh
        if nh in self.next_hop:
            intf = self.next_hop[nh]
            for ip in self.virtual_ip_intf:
                if self.virtual_ip_intf[ip] == intf:
                    return ip
        else:
            return '192.168.0.1'

    def _virtual_ip_icmp_reply(self, datapath, in_port, pkt):
        eth_hd = pkt.get_protocol(ethernet.ethernet)
        ipv4_hd = pkt.get_protocol(ipv4.ipv4)
        icmp_hd = pkt.get_protocol(icmp.icmp)
        if icmp_hd.type == icmp.ICMP_ECHO_REQUEST:
            vir_ip = ipv4_hd.dst
            if vir_ip not in self.virtual_ip:
                print ("WARNING: could be virtual ip routing table config err")
                return
            vir_mac = self.virtual_ip[vir_ip]
            icmp_reply = packet.Packet()
            icmp_reply.add_protocol(ethernet.ethernet(ethertype=eth_hd.ethertype,
                                                      dst=eth_hd.src,
                                                      src=vir_mac))
            icmp_reply.add_protocol(ipv4.ipv4(dst=ipv4_hd.src,
                                              src=vir_ip,
                                              proto=ipv4_hd.proto))
            icmp_reply.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                              code=icmp.ICMP_ECHO_REPLY_CODE,
                                              data=icmp_hd.data))
            self._send_packet_port(datapath, in_port, icmp_reply)
            
    def _icmp_nat(self, datapath, in_port, pkt):
        #check first if there is entry already
        eth_hd = pkt.get_protocol(ethernet.ethernet)
        ipv4_hd = pkt.get_protocol(ipv4.ipv4)
        icmp_hd = pkt.get_protocol(icmp.icmp)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if (icmp_hd.type != icmp.ICMP_ECHO_REQUEST and icmp_hd.type != icmp.ICMP_ECHO_REPLY):
            print("INFO: not echo type icmp caught by NAT table")
            return
        pkt_echo = icmp_hd.data
        if ipv4_hd.src in self.probe_conf:
        #outbound NAT, icmp probe packets
            probe_type, nh = self.probe_conf[ipv4_hd.src].split('@')
            if nh not in self.mac_table:
                print("INFO: ICMP probe packet dropped, next-hop mac not known")
                self._arp_request(datapath, in_port, pkt)
                return
            pair = ipv4_hd.src + ':' + str(pkt_echo.id)
            if pair in self.nat_icmp_in2out:
                pair_nat = self.nat_icmp_in2out[pair]
                ip_src_nat, echo_id_nat_str = pair_nat.split(':')
                echo_id_nat = int(echo_id_nat_str)
            else:
                if probe_type == 'PIP':
                    ip_src_nat = self._find_vip_from_nh(nh)
                else:
                    ip_src_nat = self.nat_ip
                echo_id_nat = self._find_icmp_id(ip_src_nat)
                if not echo_id_nat:
                    print("ERROR: no more availble icmp id for nat: %s" % pair)
                    return
                pair_nat = ip_src_nat + ':' + str(echo_id_nat)
                self.nat_icmp_in2out[pair] = pair_nat
                self.nat_icmp_out2in[pair_nat] = pair
                self.used_id[ip_src_nat].append(echo_id_nat)
            out_port = int(self.next_hop[nh].split(':')[1])
            dst_mac = self.mac_table[nh]
            new_icmp = packet.Packet()
            new_icmp.add_protocol(ethernet.ethernet(ethertype=eth_hd.ethertype,
                                                    dst=dst_mac,
                                                    src=self.virtual_ip[ip_src_nat]))
            new_icmp.add_protocol(ipv4.ipv4(dst=ipv4_hd.dst,
                                            src=ip_src_nat,
                                            proto=ipv4_hd.proto))
            pkt_echo_nat = pkt_echo
            pkt_echo_nat.id = echo_id_nat
            new_icmp.add_protocol(icmp.icmp(type_=icmp_hd.type,
                                            code=icmp_hd.code,
                                            csum=icmp_hd.csum,
                                            data=pkt_echo_nat))
            actions = [parser.OFPActionOutput(out_port)]
            self._send_packet_action(datapath, actions, new_icmp)
        elif IPAddress(ipv4_hd.src) in IPNetwork('192.168.0.0/24'):
            #outboudn icmp, private address but other than probe
            ip_src_nat = self.nat_ip
            nh, out_port = self._find_nh(datapath, ipv4_hd.src, ipv4_hd.dst)
            pair = ipv4_hd.src + ':' + str(pkt_echo.id)
            if nh not in self.mac_table:
                print("INFO: ICMP packet dropped, next-hop mac not known")
                self._arp_request(datapath, in_port, pkt)
                return
            pair = ipv4_hd.src + ':' + str(pkt_echo.id)
            if pair in self.nat_icmp_in2out:
                pair_nat = self.nat_icmp_in2out[pair]
                ip_src_nat, echo_id_nat_str = pair_nat.split(':')
                echo_id_nat = int(echo_id_nat_str)
            else:
                echo_id_nat = self._find_icmp_id(ip_src_nat)
                if not echo_id_nat:
                    print("ERROR: not more availble icmp id for NAT: %s" % pair)
                    return
                pair_nat = ip_src_nat + ':' + str(echo_id_nat)
                self.nat_icmp_in2out[pair] = pair_nat
                self.nat_icmp_out2in[pair_nat] = pair
                self.used_id[ip_src_nat].append(echo_id_nat)
            dst_mac = self.mac_table[nh]
            new_icmp = packet.Packet()
            new_icmp.add_protocol(ethernet.ethernet(ethertype=eth_hd.ethertype,
                                                    dst=dst_mac,
                                                    src=self.virtual_ip[ip_src_nat]))
            new_icmp.add_protocol(ipv4.ipv4(dst=ipv4_hd.dst,
                                            src=ip_src_nat,
                                            proto=ipv4_hd.proto))
            pkt_echo_nat = pkt_echo
            pkt_echo_nat.id = echo_id_nat
            #print 'DEBUG:', type(pkt_echo_nat.id), type(pkt_echo_nat.seq) 
            new_icmp.add_protocol(icmp.icmp(type_=icmp_hd.type,
                                            code=icmp_hd.code,
                                            csum=icmp_hd.csum,
                                            data=pkt_echo_nat))
            actions = [parser.OFPActionOutput(int(out_port))]
            self._send_packet_action(datapath, actions, new_icmp)
        elif ipv4_hd.dst in self.virtual_ip:
            pair = ipv4_hd.dst + ':' + str(pkt_echo.id)
            if pair in self.nat_icmp_out2in:
                ip_dst_nat, echo_id_nat_str = self.nat_icmp_out2in[pair].split(':')
                echo_id_nat = int(echo_id_nat_str)
                out_port = 1
            else:
                print("INFO: inbound icmp NAT miss, could be for VIR IP, directed to VIR IP logic")
                self._virtual_ip_icmp_reply(datapath, in_port, pkt)
                return
            new_icmp = packet.Packet()
            new_icmp.add_protocol(ethernet.ethernet(ethertype=eth_hd.ethertype,
                                                    dst=eth_hd.dst,
                                                    src=eth_hd.src))
            new_icmp.add_protocol(ipv4.ipv4(dst=ip_dst_nat,
                                            src=ipv4_hd.src,
                                            proto=ipv4_hd.proto))
            pkt_echo_nat = pkt_echo
            pkt_echo_nat.id = echo_id_nat
            new_icmp.add_protocol(icmp.icmp(type_=icmp_hd.type,
                                            code=icmp_hd.code,
                                            csum=icmp_hd.csum,
                                            data=pkt_echo_nat))
            actions = [parser.OFPActionOutput(out_port)]
            self._send_packet_action(datapath, actions, new_icmp)


    def _tcp_nat(self, datapath, in_port, pkt):
        eth_hd = pkt.get_protocol(ethernet.ethernet)
        ipv4_hd = pkt.get_protocol(ipv4.ipv4)
        tcp_hd = pkt.get_protocol(tcp.tcp)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        
        if ipv4_hd.src in self.probe_conf:
            print("DEBUG: Outgoing probe packet NAT flow table miss")
            # out going probe packet
            pair = ipv4_hd.src + ':' + str(tcp_hd.src_port)
            probe_type, nh = self.probe_conf[ipv4_hd.src].split('@')
            if nh not in self.mac_table:
                print("INFO: TCP probe packet dropped, next-hop mac not known")
                self._arp_request(datapath, in_port, pkt)
                return
            dst_mac = self.mac_table[nh]
            out_port = int(self.next_hop[nh].split(':')[1])
            if pair in self.nat_tcp_in2out:
                ip_src_nat, src_port_nat_str = self.nat_tcp_in2out[pair].split(':')
                src_port_nat = int(src_port_nat_str)
            else:
                if probe_type == 'PIP':
                    ip_src_nat = self._find_vip_from_nh(nh)
                else:
                    ip_src_nat = self.nat_ip
                src_port_nat = self._find_tcp_port(ip_src_nat)
                if not src_port_nat:
                    print("ERROR: no more available tcp port for NAT: %s" % pair)
                    return
                pair_nat = ip_src_nat + ':' +str(src_port_nat)
                self.nat_tcp_in2out[pair]=pair_nat
                self.nat_tcp_out2in[pair_nat]=pair
                self.used_port[ip_src_nat].append(src_port_nat)
            #outgoing flow
            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=0x800,
                                    ipv4_src=ipv4_hd.src,
                                    ip_proto=inet.IPPROTO_TCP,
                                    tcp_src=tcp_hd.src_port)
            actions = [parser.OFPActionSetField(ipv4_src=ip_src_nat),
                       parser.OFPActionSetField(tcp_src=src_port_nat)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(2)]
            self._add_flow(datapath, 1, 20, 300, match, inst)
            actions.append(parser.OFPActionSetField(eth_dst=dst_mac))
            actions.append(parser.OFPActionOutput(out_port))
            self._send_packet_action(datapath, actions, pkt)
            #incoming flow
            match = parser.OFPMatch(eth_type=0x800,
                                    ipv4_dst=ip_src_nat,
                                    ip_proto=inet.IPPROTO_TCP,
                                    tcp_dst=src_port_nat)
            actions = [parser.OFPActionSetField(ipv4_dst=ipv4_hd.src),
                       parser.OFPActionSetField(tcp_dst=tcp_hd.src_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(2)]
            self._add_flow(datapath, 1, 20, 300, match, inst)
        elif IPAddress(ipv4_hd.src) in IPNetwork('192.168.0.0/24'):
            #out going tcp packet having private address other then probe packet
            print("DEBUG: Outgoing normal packet NAT flow table miss")
            pair = ipv4_hd.src + ':' + str(tcp_hd.src_port)
            ip_src_nat = self.nat_ip
            nh, out_port = self._find_nh(datapath, ipv4_hd.src, ipv4_hd.dst)
            if nh not in self.mac_table:
                print("INFO: TCP packet dropped, next-hop mac not known")
                self._arp_request(datapath, in_port, pkt)
                return
            dst_mac = self.mac_table[nh]
            if pair in self.nat_tcp_in2out:
                ip_src_nat, src_port_nat_str = self.nat_tcp_in2out[pair].split(':')
                src_port_nat = int(src_port_nat_str)
            else:
                src_port_nat = self._find_tcp_port(ip_src_nat)
                if not src_port_nat:
                    print("ERROR: no more available tcp port for NAT: %s" % pair)
                    return
                pair_nat = ip_src_nat + ':' +str(src_port_nat)
                self.nat_tcp_in2out[pair]=pair_nat
                self.nat_tcp_out2in[pair_nat]=pair
                self.used_port[ip_src_nat].append(src_port_nat)
            #outgoing flow
            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=0x800,
                                    ipv4_src=ipv4_hd.src,
                                    ip_proto=inet.IPPROTO_TCP,
                                    tcp_src=tcp_hd.src_port)
            actions = [parser.OFPActionSetField(ipv4_src=ip_src_nat),
                       parser.OFPActionSetField(tcp_src=src_port_nat)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(2)]
            self._add_flow(datapath, 1, 20, 300, match, inst)
            actions.append(parser.OFPActionSetField(eth_dst=dst_mac))
            actions.append(parser.OFPActionOutput(out_port))
            self._send_packet_action(datapath, actions, pkt)
            #incoming flow
            match = parser.OFPMatch(eth_type=0x800,
                                    ipv4_dst=ip_src_nat,
                                    ip_proto=inet.IPPROTO_TCP,
                                    tcp_dst=src_port_nat)
            actions = [parser.OFPActionSetField(ipv4_dst=ipv4_hd.src),
                       parser.OFPActionSetField(tcp_dst=tcp_hd.src_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(2)]
        elif ipv4_hd.dst in self.virtual_ip:
            #incoming TCP packet
            pair = ipv4_hd.dst + ':' + str(tcp_hd.dst_port)
            if pair not in self.nat_tcp_out2in:
                print("INFO: inbound TCP NAT miss")
                return
            ip_dst_nat, dst_port_nat_str = self.nat_tcp_out2in[pair].split(':')
            dst_port_nat = int(dst_port_nat_str)
            out_port = 1
            match = parser.OFPMatch(eth_type=0x800,
                                    ipv4_dst=ipv4_hd.dst,
                                    ip_proto=inet.IPPROTO_TCP,
                                    tcp_dst=tcp_hd.dst_port)
            actions = [parser.OFPActionSetField(ipv4_dst=ip_dst_nat),
                       parser.OFPActionSetField(tcp_dst=dst_port_nat)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(2)]
            print('DEBUG: Incoming packets NAT flow table miss')
            self._add_flow(datapath, 1, 20, 300, match, inst)
            actions.append(parser.OFPActionOutput(out_port))
            self._send_packet_action(datapath, actions, pkt)          
    
    def _find_tcp_port(self, ip_src_nat):
        if ip_src_nat not in self.used_port:
            self.used_port[ip_src_nat] = []
        i= 1
        src_port_nat = 0
        for n in range(0,16):
            temp = randint(1500,65535)
            if temp not in self.used_port[ip_src_nat]:
                src_port_nat = temp
                break
        return src_port_nat

    def _find_icmp_id(self, ip_src_nat):
        if ip_src_nat not in self.used_id:
            self.used_id[ip_src_nat] = []
        i= 1
        echo_id_nat = 0
        for n in range(0,16):
            temp = randint(1,65535)
            if temp not in self.used_id[ip_src_nat]:
                echo_id_nat = temp
                break
        return echo_id_nat

    def _add_flow(self, datapath, table_id, priority, idle_timeout, match, inst):
        parser = datapath.ofproto_parser
        #inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        print("INFO: Flow Install")
        print("    dpid %d; table_id: %d; priority: %d; idle_timeout: %d" % (datapath.id, table_id, priority, idle_timeout))
        print("    Match: %s\n    Instructions:%s" % (match, inst))
        mod = parser.OFPFlowMod(datapath=datapath,
                                table_id = table_id,
                                idle_timeout=idle_timeout,
                                priority=priority,
                                match=match,
                                instructions=inst)      
        datapath.send_msg(mod)
 
    def _send_packet_action(self, datapath, actions, packet):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        packet.serialize()
        data = packet.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def _send_packet_port(self, datapath, port, packet):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        packet.serialize()
        data = packet.data
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print ("INFO: dpid = %s, flow tables init" % str(datapath.id))
        if datapath.id == 1 or datapath.id == 2:
            #bgp router
            #catch arp (table_id = 0)
            match = parser.OFPMatch(eth_type=0x806)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 0, 10, 0, match, inst)
            #pass ipv4
            match = parser.OFPMatch(eth_type=0x800)
            inst = [parser.OFPInstructionGotoTable(1)]
            self._add_flow(datapath, 0, 10, 0, match, inst)
            #drop the rest
            match = parser.OFPMatch()
            actions = [] #drop
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 0, 0, 0, match, inst)
            #NAT(table_id = 1)
            # src_ip in 192.168.0/24, from inside -> controller
            match = parser.OFPMatch(in_port=1,
                                    eth_type=0x800,
                                    ipv4_src=('192.168.0.0',
                                              '255.255.255.0'))
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 1, 10, 0, match, inst)
            # dst_ip = nat ip, from outside -> controller
            #nat_ip = ''
            for ip in self.virtual_ip_intf:
                if 'nat' in self.virtual_ip_intf[ip]:
                    self.nat_ip = ip
                    break
            match = parser.OFPMatch(in_port=2,
                                    eth_type=0x800,
                                    ipv4_dst=self.nat_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 1, 10, 0, match, inst)
            match = parser.OFPMatch(in_port=3,
                                    eth_type=0x800,
                                    ipv4_dst = self.nat_ip)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 1, 10, 0, match, inst)
            #dst_ip = virt ip/interco
            for ip in self.virtual_ip_intf:
                if len(self.virtual_ip_intf[ip].split(':')) == 2 and int(self.virtual_ip_intf[ip].split(':')[0]) == datapath.id:
                    match = parser.OFPMatch(in_port=int(self.virtual_ip_intf[ip].split(':')[1]),
                                            eth_type=0x800,
                                            ipv4_dst=ip)
                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                      ofproto.OFPCML_NO_BUFFER)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    self._add_flow(datapath, 1, 10, 0, match, inst)
            #table miss entry -> go to PBR table (1), with lowest priority
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(2)]
            self._add_flow(datapath, 1, 0, 0, match, inst)
            #PBR(table_id = 2)
            #probe ip -> out_port, metadate = nh_ip for mac calc, go to mac table (4)
            #table miss go to route table (3)     
            for ip in self.probe_conf:
                nh = self.probe_conf[ip].split('@')[1]
                dpid, port_no = self.next_hop[nh].split(':')
                if dpid == str(datapath.id):
                    match = parser.OFPMatch(in_port=1,
                                            eth_type=0x800,
                                            ipv4_src=ip)
                    actions = [parser.OFPActionOutput(int(port_no))]
                    #print 'DEBUG:', bin(int(IPAddress(nh))), bin(0xffffffffffffffff)
                    inst = [parser.OFPInstructionWriteMetadata(int(IPAddress(nh)), 0xffffffffffffffff),
                            parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions),
                            parser.OFPInstructionGotoTable(4)]
                    self._add_flow(datapath, 2, 10, 0, match, inst)
            #table miss entry, go to routing table (3)
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(3)]
            self._add_flow(datapath, 2, 0, 0, match, inst)
            #routing table (table_id=3)
            #route for directly connected next_hop, out, metadata, mac table (4)
            for ip in self.next_hop:
                dpid, port = self.next_hop[ip].split(':')
                if dpid == str(datapath.id):
                    match = parser.OFPMatch(eth_type=0x800,
                                            ipv4_dst=ip)
                    actions = [parser.OFPActionOutput(int(port))]
                    inst = [parser.OFPInstructionWriteMetadata(int(IPAddress(ip)), 0xffffffffffffffff),
                            parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions),
                            parser.OFPInstructionGotoTable(4)]
                    self._add_flow(datapath, 3, 20, 0, match, inst)
            #route for virtual ips, go to controller directly
            for ip in self.virtual_ip_intf:
                if datapath.id == self.virtual_ip_intf[ip].split(':')[0]:
                    match = parser.OFPMatch(eth_type=0x800,
                                            ipv4_dst=ip)
                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                      ofproto.OFPCML_NO_BUFFER)]
                    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    self._add_flow(datapath, 3, 20, 0, match, inst)
            #192.168.0.0 -> out aply
            match = parser.OFPMatch(eth_type=0x800,
                                    ipv4_dst=('192.168.0.0',
                                              '255.255.255.0'))
            actions = [parser.OFPActionOutput(1)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 3, 10, 0, match, inst)
            #default route -> out_port, metadata, go to mac table (4)
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(2)]
            nh = ''
            for ip in self.next_hop:
                dpid, port = self.next_hop[ip].split(':')
                if dpid == str(datapath.id) and int(port) == 2:
                    nh = ip
                    #print("DEBUG: %s" % nh)
                    break
            inst = [parser.OFPInstructionWriteMetadata(int(IPAddress(nh)), 0xffffffffffffffff),
                    parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(4)]
            self._add_flow(datapath, 3, 0, 0, match, inst)
            #mac table (table_id=4)
            #match(metadata=int(IPAddress(nh))), set mac_dst->self.mac_table[nh]
            #table miss -> clear previous avtion list -> goto an additional table
            match = parser.OFPMatch()
            actions=[]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(5)]
            self._add_flow(datapath, 4, 0, 0, match, inst)
            #additional table 5, all mac miss packet send back to controller in its initial form
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 5, 0, 0, match, inst)
        if datapath.id ==3:
            #local as network
            #catch arp (table_id = 0)
            match = parser.OFPMatch(eth_type=0x806)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 0, 10, 0, match, inst)
            #pass ipv4
            match = parser.OFPMatch(eth_type=0x800)
            inst = [parser.OFPInstructionGotoTable(1)]
            self._add_flow(datapath, 0, 10, 0, match, inst)
            #drop the rest
            match = parser.OFPMatch()
            actions = [] #drop
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 0, 0, 0, match, inst)
            #PBR for probe (table_id = 1)
            #for src ip in pbr, if nh dp = 1
            for ip in self.probe_conf:
                nh = self.probe_conf[ip].split('@')[1]
                nh_dpid = self.next_hop[nh].split(':')[0]
                if nh_dpid == '1':
                    out_port = 2
                else:
                    out_port = 3
                match = parser.OFPMatch(eth_type=0x800,
                                        ipv4_src=ip)
                actions = [parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self._add_flow(datapath, 1, 10, 0, match, inst)
            #pbr table  miss, go to routing table (2)
            match = parser.OFPMatch()
            inst = [parser.OFPInstructionGotoTable(2)]
            self._add_flow(datapath, 1, 0, 0, match, inst)
            #route table (table_id = 2)
            #route for gw, should go to controller
            gw = ''
            for ip in self.virtual_ip_intf:
                if 'gw' in self.virtual_ip_intf[ip]:
                    gw = ip
                    break
            match = parser.OFPMatch(eth_type=0x800,
                                    ipv4_dst=gw)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 2, 20, 0, match, inst)
            #route for nf, out, apply
            for ip in self.next_hop:
                nh_dpid = self.next_hop[ip].split(':')[0]
                if nh_dpid == '1':
                    out_port = 2
                else:
                    out_port = 3
                match = parser.OFPMatch(eth_type=0x800,
                                        ipv4_dst=ip)
                actions = [parser.OFPActionOutput(out_port)]
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                self._add_flow(datapath, 2, 20, 0, match, inst)
            #route for 192.168.0.0/24, out port and go to mac table (2)
            match = parser.OFPMatch(eth_type=0x800,
                                    ipv4_dst=('192.168.0.0',
                                              '255.255.255.0'))
            actions = [parser.OFPActionOutput(1)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS, actions),
                    parser.OFPInstructionGotoTable(3)]
            self._add_flow(datapath, 2, 10, 0, match, inst)
            #default route
            match = parser.OFPMatch()
            actions =[parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 2, 0, 0, match, inst)
            #mac table (table_id = 3)
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [#parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS,[]),
                    parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self._add_flow(datapath, 3, 0, 0, match, inst)



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        table_id = msg.table_id
        pkt = packet.Packet(msg.data)
        in_port = msg.match['in_port']
        #catch arp
        if table_id == 0:
            arp_hd = pkt.get_protocol(arp.arp)
            if not arp_hd:
                return
            self._arp_handler(datapath, in_port, pkt)
        #TCP nat entry miss or ICMP nat
        if (datapath.id == 1 or datapath.id == 2) and table_id == 1:
            ipv4_hd = pkt.get_protocol(ipv4.ipv4)
            if ipv4_hd.proto == inet.IPPROTO_ICMP:
                self._icmp_nat(datapath, in_port, pkt)
            elif ipv4_hd.proto == inet.IPPROTO_TCP:
                self._tcp_nat(datapath, in_port, pkt)
        #virtual_ip icmp reply
        if (datapath.id == 3 and table_id == 2) or ((datapath.id == 1 or datapath.id == 2) and table_id == 3):
            ipv4_hd = pkt.get_protocol(ipv4.ipv4)
            if ipv4_hd.proto == inet.IPPROTO_ICMP:
                #if icmp request, reply with icmp echo reply
                self._virtual_ip_icmp_reply(datapath, in_port, pkt)
        #mac table miss
        if (datapath.id == 3 and table_id == 3) or ((datapath.id == 1 or datapath.id == 2) and table_id == 5):
            self._arp_request(datapath, in_port, pkt)

