from netfilterqueue import NetfilterQueue
from scapy.layers.inet import *
from scapy.all import *
import pandas as pd
import pickle

def detectDdos(json_dict):
    
    inputSet = pd.DataFrame(json_dict)
    inputSet['new_SRC_IP'] = [''.join(x.split(".")) for x in inputSet['Src IP']]
    inputSet['new_DST_IP'] = [''.join(x.split(".")) for x in inputSet['Dst IP']]
    inputSet['new_Timestamp'] = [''.join((x.split()[0]).split("/"))+''.join(((x.split()[1]).split(":"))[0]) for x in inputSet['Timestamp']]
    
    X = inputSet.drop(['Timestamp','Src IP','Dst IP'], axis='columns')
    with open("Model/Detect_DDoS.pickle", "rb") as pickle_model:
        model = pickle.load(pickle_model)  
    result = model.predict(X)
    return result


def firewall(packet):
    IP_pkt = IP(packet.get_payload())
    timeStamp_end = packet.get_timestamp()
    print(IP_pkt[0].show())
    inter_arrival_time = int((timestamp_start - timeStamp_end) * 1000) #get IAT
    timestamp_start = packet.get_timestamp()
    #based on average forwarded packets and average initial bandwidth window bytes
    tot_fwd_pkts = 4
    int_bwd_win_bytes = 4759
    
    if IP_pkt.haslayer(TCP):
        IP_pkt.getlayer(TCP)
        print(IP_pkt.sport) #get source_port
        tcp_payload_len = len(IP_pkt[TCP].payload)
        if IP_pkt.haslayer(Padding):
            tcp_payload_len -= len(IP_pkt[Padding]) #total segment size
    if IP_pkt.haslayer(UDP):
        IP_pkt.getlayer(UDP)
        print(IP_pkt.sport)
        tcp_payload_len = len(IP_pkt[UDP].payload)
        if IP_pkt.haslayer(Padding):
            tcp_payload_len -= len(IP_pkt[Padding])
    
    json_dict = {'Fwd Seg Size Min':[tcp_payload_len],
                 'Flow IAT Min':[inter_arrival_time],
                 'Src Port':[int(IP_pkt.sport)],
                 'Tot Fwd Pkts':[tot_fwd_pkts],
                 'Init Bwd Win Byts':[int_bwd_win_bytes],
                 'Src IP':[IP_pkt.src],
                 'Dst IP':[IP_pkt.dst],
                 'Timestamp':[timeStamp_end]}
    
    if detectDdos(json_dict) == 'ddos':
        packet.drop()
    else:
        packet.accept()
    

nfqueue = NetfilterQueue()
nfqueue.bind(1,firewall)

try:
    global timestamp_start
    timestamp_start = datetime.datetime.now()
    nfqueue.run()
except KeyboardInterrupt:
    exit()




