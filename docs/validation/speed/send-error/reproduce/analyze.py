"""Read existing PCAP/log evidence only; no packets or external actions."""
from pathlib import Path
import collections,gzip,hashlib,json,re,struct,socket
work=Path(__file__).resolve().parent.parent
summary={}
def capture(path):
 data=gzip.decompress((work/'pcap'/(path.name+'.gz')).read_bytes());off=24;ports=collections.Counter();flags=collections.Counter();times=[];frames=[]
 while off<len(data):
  sec,usec,n,original=struct.unpack_from('<IIII',data,off);off+=16;b=data[off:off+n];off+=n
  if len(b)<54 or b[12:14]!=b'\x08\x00' or b[23]!=6:continue
  tcp=14+(b[14]&15)*4
  src=socket.inet_ntoa(b[26:30]);dst=socket.inet_ntoa(b[30:34]);f=b[tcp+13]
  flags[src+'->'+dst+' '+hex(f)]+=1
  if src=='198.18.0.3' and dst=='198.18.0.2' and f==2:
   port=struct.unpack_from('!H',b,tcp+2)[0];ports[port]+=1;times.append(sec+usec/1e6)
   if len(frames)<2:frames.append({'timestamp':sec+usec/1e6,'destination_port':port,'complete_frame_hex':b.hex(' '),'captured_length':n,'original_length':original})
 return {'SYN':sum(ports.values()),'unique_SYN_ports':len(ports),'port_set':set(ports),'each_port_once':bool(ports) and max(ports.values())==1,'SYN_span_seconds':max(times)-min(times) if len(times)>1 else None,'TCP_flags':dict(flags),'first_two_full_SYN_frames':frames}
for case in ('persistent-original','persistent-fixed','transient-fixed','normal-cold'):
 stderr=(work/'logs'/(case+'.stderr')).read_text();exitcode=int((work/'logs'/(case+'.exit')).read_text());expected=set(range(1,65536)) if case=='normal-cold' else set(range(8000,8256))
 row={'exit':exitcode,'timing':(work/'logs'/(case+'.time')).read_text().strip(),'send_logs':re.findall(r'(?:scan_send:|send_inject:)[^\r\n]*',stderr),'open8080': 'open tcp 8080 ' in (work/'logs'/(case+'.list')).read_text(),'sides':{}}
 for side in ('source','target'):
  result=capture(work/(case+'-'+side+'.pcap'));result['expected_exact_port_set']=result.pop('port_set')==expected
  stats=(work/'logs'/(case+'-'+side+'-capture.log')).read_text().strip();result['capture_stats']=stats;assert 'kernel_drops=0' in stats
  row['sides'][side]=result
 if case=='persistent-original':
  assert exitcode==0 and all(r['SYN']==0 for r in row['sides'].values()) and 'selected_calls=256 injected_failures=256 forwarded_successes=0' in stderr
  row['false_success_reproduced']=True;row['injection_source_version']='attempt4/inject-send.c v1; persistent mode semantics unchanged;256ENOBUFS, no actual SYN forwarded'
 elif case=='persistent-fixed':
  assert exitcode==1 and all(r['SYN']==0 for r in row['sides'].values()) and 'fatal failed_calls=8 retries=7 attempts=8 errno=105' in stderr
  assert len(re.findall('same_as_first=1',stderr))==8
 elif case=='transient-fixed':
  assert exitcode==0 and row['open8080'] and all(r['expected_exact_port_set'] and r['each_port_once'] for r in row['sides'].values())
  failed=int(re.search(r'injected_failures=(\d+)',stderr).group(1));assert 2<failed<8
  assert f'call={failed+1} same_as_first=1' in stderr and f'stats failed_calls={failed} retries={failed}' in stderr
  row['continuous_EAGAIN_ms']=40;row['same_packet_recovered_after_failed_calls']=failed
 else:
  assert exitcode==0 and row['open8080'] and all(r['SYN']==65535 and r['expected_exact_port_set'] and r['each_port_once'] for r in row['sides'].values())
  assert 'stats failed_calls=0 retries=0 phase=rx_shutdown' in stderr
  row['configured_PPS']=10000;row['cold_definition']='fresh namespace/underlay veth/VXLAN per case; no ping or warmup scan; not a100IP/5Worker cloud model'
 summary[case]=row
report={'passed':True,'scope':'Local Linuxamd64 privateDocker --network none, AF_PACKET+kernelVXLAN; controlled fault injection and one normal65535-port10k cold case only','R5_causality':'NOT established. This demonstrates ignored send-error propagation, not the cause ofR5 deficit; local cold case cannot reproduce/attribute the cloud gap.','Agent_path':'SOURCE REVIEW ONLY: cmd.Wait nonzero returns masscan failed before capture-stat acceptance; Agent/Control integration was not executed here.','counter_semantics':'Per-adapter failed sendpacket calls/retries. phase=rx_shutdown is a snapshot, not a final total of all possible subsequent send calls. Successful sendpacket does not prove remote delivery.','cases':summary}
(work/'summaries/recomputed-local-summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:{'exit':v['exit'],'SYN':{s:d['SYN'] for s,d in v['sides'].items()},'open8080':v['open8080'],'send_logs':v['send_logs']} for k,v in summary.items()},indent=2))
