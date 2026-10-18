import collections,json,struct,socket
from pathlib import Path
base=Path(__file__).resolve().parent.parent/"pcap"
results={}
def checksum(b):
    if len(b)%2:b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b))
    while s>>16:s=(s&65535)+(s>>16)
    return (~s)&65535
for name in ['mixed-default','mixed-candidate']:
    data=(base/(name+'.pcap')).read_bytes();off=24;frames=[];counts=collections.Counter();synseq=None
    while off<len(data):
        sec,usec,n,original=struct.unpack_from('<IIII',data,off);off+=16;frame=data[off:off+n];off+=n
        if len(frame)<54 or frame[12:14]!=b'\x08\x00':continue
        ip=frame[14:];h=(ip[0]&15)*4
        if ip[9]!=6:continue
        tcp=ip[h:struct.unpack_from('!H',ip,2)[0]];sport,dport,seq,ack=struct.unpack_from('!HHII',tcp);flags=tcp[13]
        src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]);direction='scanner' if src=='198.18.0.3' else 'target'
        counts[direction+'_flags_'+hex(flags)]+=1
        if direction=='scanner' and flags==2:synseq=seq
        if direction=='target':
            assert ack==(synseq+1)%2**32, 'wrong syn cookie echo'
            assert checksum(ip[:h])==0, 'invalid IP checksum'
            assert checksum(ip[12:20]+b'\x00\x06'+struct.pack('!H',len(tcp))+tcp)==0, 'invalid TCP checksum'
        frames.append({'timestamp':sec+usec/1e6,'source':f'{src}:{sport}','destination':f'{dst}:{dport}','flags':hex(flags),'sequence':seq,'ack':ack,'full_frame_hex':frame.hex(' ')})
    expected_rst=1 if name=='mixed-default' else 0
    assert counts['scanner_flags_0x2']==1 and counts['target_flags_0x16']==1 and counts['scanner_flags_0x4']==expected_rst, counts
    assert 'open tcp' not in (base.parent/'logs'/(name+'.list')).read_text(), 'RST combination became open evidence'
    results[name]={'counts':dict(counts),'valid_SYN_cookie_echo_and_checksums':True,'no_open_evidence':True,'frames':frames,'capture':(base.parent/'logs'/(name+'-capture.log')).read_text().strip()}
(base.parent/'summaries/reproduced-mixed-summary.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2))
