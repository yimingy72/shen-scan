import collections, json, struct, socket
from pathlib import Path
base=Path(__file__).resolve().parent.parent/"pcap"
results={}
for name in ['default','noreset','silent','candidate']:
    path=base/(name+'.pcap')
    if not path.exists(): continue
    data=path.read_bytes(); endian='<' if data[:4]==bytes.fromhex('d4c3b2a1') else '>'
    off=24; counters=collections.Counter(); ports=collections.Counter(); times=[]; open_resets=0; closed_resets=0
    while off<len(data):
        sec,usec,n,original=struct.unpack_from(endian+'IIII',data,off); off+=16; frame=data[off:off+n];off+=n
        if len(frame)<54 or frame[12:14]!=b'\x08\x00': continue
        ip=frame[14:]; hlen=(ip[0]&15)*4
        if ip[9]!=6 or len(ip)<hlen+20: continue
        src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]); tcp=ip[hlen:]
        sport,dport=struct.unpack_from('!HH',tcp);flags=tcp[13];direction='scanner' if src=='198.18.0.3' else 'target'
        counters[direction+'_flags_'+hex(flags)]+=1
        if direction=='scanner' and flags==2:
            ports[dport]+=1;times.append(sec+usec/1e6)
        if direction=='scanner' and flags&4:
            if dport==8080:open_resets+=1
            else:closed_resets+=1
    span=max(times)-min(times)
    results[name]={'packets_by_TCP_flags':dict(counters),'SYN_count':sum(ports.values()),'unique_SYN_ports':len(ports),'exact_1_to_12000_once':set(ports)==set(range(1,12001)) and max(ports.values())==1,'SYN_first_to_last_seconds':span,'active_SYN_per_second':(len(times)-1)/span,'scanner_RST_to_closed_ports':closed_resets,'scanner_RST_to_open_8080':open_resets,'timing':(base.parent/'logs'/(name+'.time')).read_text().strip(),'capture':(base.parent/'logs'/(name+'-capture.log')).read_text().strip(),'open_list':(base.parent/'logs'/(name+'.list')).read_text().strip()}
print(json.dumps(results,indent=2))
(base.parent/'summaries/reproduced-micro-summary.json').write_text(json.dumps(results,indent=2)+'\n')
