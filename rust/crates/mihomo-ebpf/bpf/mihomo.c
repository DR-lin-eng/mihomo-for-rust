/* TC programs for Clash-compatible redirect-to-tun and auto-redir.
 * GPL-3.0-or-later. No CO-RE or kernel-private structures are used.
 */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct params { __u32 mark, tun_index; __u8 redir4[4], redir6[16]; __u16 port; __u16 pad; };
struct flow_key { __u8 source[16], proxy[16]; __u16 source_port, proxy_port; __u32 family; };
struct origin { __u8 address[16]; __u16 port; __u16 pad; };
struct counters { __u64 processed, redirected, bypassed, dropped; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct params); } config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,65536); __type(key,struct flow_key); __type(value,struct origin); } origins SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1024); __type(key,__u32); __type(value,__u32); } local4 SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1024); __type(key,struct origin); __type(value,__u32); } local6 SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct counters); } stats SEC(".maps");

struct packet { __u32 ip, tcp, family; __u8 proto, flags; __u16 source_port, dest_port; __u8 source[16],dest[16]; };
static __always_inline void count(int field) {
 __u32 zero=0; struct counters *c=bpf_map_lookup_elem(&stats,&zero); if(!c)return;
 if(field==0)__sync_fetch_and_add(&c->processed,1);
 else if(field==1)__sync_fetch_and_add(&c->redirected,1);
 else if(field==2)__sync_fetch_and_add(&c->bypassed,1);
 else __sync_fetch_and_add(&c->dropped,1);
}
static __always_inline int pass(void){count(2);return TC_ACT_OK;}
static __always_inline int drop(void){count(3);return TC_ACT_SHOT;}
static __always_inline int parse(struct __sk_buff *skb,struct packet *p) {
 __u16 protocol; if(bpf_skb_load_bytes(skb,12,&protocol,2)<0)return -1;
 __u32 offset=14;
 #pragma unroll
 for(int i=0;i<2;i++) {if(protocol==bpf_htons(ETH_P_8021Q)||protocol==bpf_htons(ETH_P_8021AD)){
  if(bpf_skb_load_bytes(skb,offset+2,&protocol,2)<0)return -1;offset+=4;
 }}
 p->ip=offset;
 if(protocol==bpf_htons(ETH_P_IP)){
  __u8 header[20];if(bpf_skb_load_bytes(skb,offset,header,20)<0)return -1;
  __u32 ihl=(header[0]&15)*4;if((header[0]>>4)!=4||ihl<20)return -1;
  __u16 frag;__builtin_memcpy(&frag,&header[6],2);if(bpf_ntohs(frag)&0x3fff)return -1;
  p->family=4;p->proto=header[9];__builtin_memcpy(p->source,&header[12],4);__builtin_memcpy(p->dest,&header[16],4);p->tcp=offset+ihl;
 }else if(protocol==bpf_htons(ETH_P_IPV6)){
  __u8 header[40];if(bpf_skb_load_bytes(skb,offset,header,40)<0||(header[0]>>4)!=6)return -1;
  p->family=6;p->proto=header[6];__builtin_memcpy(p->source,&header[8],16);__builtin_memcpy(p->dest,&header[24],16);p->tcp=offset+40;
  /* Bounded extension traversal; fragmented/AH/ESP packets stay on the normal path. */
  #pragma unroll
  for(int i=0;i<4;i++){if(p->proto==0||p->proto==43||p->proto==60){
   __u8 ext[2];if(bpf_skb_load_bytes(skb,p->tcp,ext,2)<0)return -1;p->proto=ext[0];p->tcp+=((__u32)ext[1]+1)*8;
  }}
 }else return -1;
 if(p->proto!=IPPROTO_TCP&&p->proto!=IPPROTO_UDP)return -1;
 __u8 ports[4];if(bpf_skb_load_bytes(skb,p->tcp,ports,4)<0)return -1;
 __builtin_memcpy(&p->source_port,ports,2);__builtin_memcpy(&p->dest_port,ports+2,2);
 if(p->proto==IPPROTO_TCP){__u8 header[20];if(bpf_skb_load_bytes(skb,p->tcp,header,20)<0)return -1;if((header[12]>>4)<5)return -1;p->flags=header[13];}
 return 0;
}
static __always_inline int local_destination(struct packet *p){
 if(p->family==4){
  __u8 a=p->dest[0],b=p->dest[1];if(a==0||a==10||a==127||a>=224||(a==169&&b==254)||(a==172&&b>=16&&b<=31)||(a==192&&b==168))return 1;
  __u32 addr;__builtin_memcpy(&addr,p->dest,4);return bpf_map_lookup_elem(&local4,&addr)!=0;
 }
 __u8 a=p->dest[0],b=p->dest[1];if(a==0xff||(a&0xfe)==0xfc||(a==0xfe&&(b&0xc0)==0x80))return 1;
 __u64 first,last;__builtin_memcpy(&first,p->dest,8);__builtin_memcpy(&last,p->dest+8,8);
 if(first==0&&(last==0||last==bpf_cpu_to_be64(1)))return 1;
 struct origin key={};__builtin_memcpy(key.address,p->dest,16);return bpf_map_lookup_elem(&local6,&key)!=0;
}
SEC("classifier/tun")
int mihomo_rs_tun(struct __sk_buff *skb){
 count(0);__u32 zero=0;struct params *cfg=bpf_map_lookup_elem(&config,&zero);if(!cfg||!cfg->tun_index||skb->mark==cfg->mark||skb->ingress_ifindex==cfg->tun_index)return pass();
 struct packet p={};if(parse(skb,&p)<0||local_destination(&p))return pass();
 count(1);return bpf_redirect(cfg->tun_index,0);
}
static __always_inline int rewrite(struct __sk_buff *skb,struct packet *p,struct origin *value,int destination){
 __u32 addr_off=p->ip+(p->family==4?(destination?16:12):(destination?24:8));
 __u32 port_off=p->tcp+(destination?2:0);__u32 csum_off=p->tcp+16;
 __u8 old_addr[16]={};__u16 old_port;
 if(bpf_skb_load_bytes(skb,port_off,&old_port,2)<0)return -1;
 if(p->family==4){
  __u32 old,new; if(bpf_skb_load_bytes(skb,addr_off,&old,4)<0)return -1;__builtin_memcpy(&new,value->address,4);
  if(bpf_l4_csum_replace(skb,csum_off,old,new,BPF_F_PSEUDO_HDR|4)<0)return -1;
  if(bpf_l3_csum_replace(skb,p->ip+10,old,new,4)<0)return -1;
  if(bpf_skb_store_bytes(skb,addr_off,&new,4,0)<0)return -1;
 }else{
  if(bpf_skb_load_bytes(skb,addr_off,old_addr,16)<0)return -1;
  #pragma unroll
  for(int i=0;i<4;i++){__u32 old,new;__builtin_memcpy(&old,old_addr+i*4,4);__builtin_memcpy(&new,value->address+i*4,4);if(bpf_l4_csum_replace(skb,csum_off,old,new,BPF_F_PSEUDO_HDR|4)<0)return -1;}
  if(bpf_skb_store_bytes(skb,addr_off,value->address,16,0)<0)return -1;
 }
 if(bpf_l4_csum_replace(skb,csum_off,old_port,value->port,2)<0)return -1;
 return bpf_skb_store_bytes(skb,port_off,&value->port,2,0);
}
SEC("classifier/redir_in")
int mihomo_rs_in(struct __sk_buff *skb){
 count(0);__u32 zero=0;struct params *cfg=bpf_map_lookup_elem(&config,&zero);if(!cfg||skb->mark==cfg->mark)return pass();
 struct packet p={};if(parse(skb,&p)<0||p.proto!=IPPROTO_TCP||local_destination(&p)||p.dest_port==bpf_htons(53))return pass();
 struct origin proxy={.port=cfg->port};
 if(p.family==4){__u32 addr;__builtin_memcpy(&addr,cfg->redir4,4);if(addr==0)return pass();__builtin_memcpy(proxy.address,cfg->redir4,4);}
 else{__u64 a,b;__builtin_memcpy(&a,cfg->redir6,8);__builtin_memcpy(&b,cfg->redir6+8,8);if((a|b)==0)return pass();__builtin_memcpy(proxy.address,cfg->redir6,16);}
 struct flow_key key={.source_port=p.source_port,.proxy_port=cfg->port,.family=p.family};
 __builtin_memcpy(key.source,p.source,16);__builtin_memcpy(key.proxy,proxy.address,16);
 if((p.flags&0x12)==0x02){
  struct origin *previous=bpf_map_lookup_elem(&origins,&key);
  if(previous&&(previous->pad&3)!=3){
   int different=previous->port!=p.dest_port;
   #pragma unroll
   for(int i=0;i<16;i++){if(previous->address[i]!=p.dest[i])different=1;}
   /* Collapsing two live tuples onto one proxy tuple must never send either
      connection to the other's destination. Reject that rare port collision. */
   if(different)return drop();
  }
  struct origin dst={.port=p.dest_port};__builtin_memcpy(dst.address,p.dest,16);
  if(bpf_map_update_elem(&origins,&key,&dst,BPF_ANY)<0)return drop();
 }else{
  struct origin *stored=bpf_map_lookup_elem(&origins,&key);if(!stored)return pass();
  if(p.flags&1){struct origin updated=*stored;updated.pad|=1;bpf_map_update_elem(&origins,&key,&updated,BPF_EXIST);}
 }
 if(rewrite(skb,&p,&proxy,1)<0)return drop();
 if(p.flags&4)bpf_map_delete_elem(&origins,&key);
 count(1);return TC_ACT_OK;
}
SEC("classifier/redir_out")
int mihomo_rs_out(struct __sk_buff *skb){
 count(0);struct packet p={};if(parse(skb,&p)<0||p.proto!=IPPROTO_TCP)return pass();
 struct flow_key key={.source_port=p.dest_port,.proxy_port=p.source_port,.family=p.family};
 __builtin_memcpy(key.source,p.dest,16);__builtin_memcpy(key.proxy,p.source,16);
 struct origin *stored=bpf_map_lookup_elem(&origins,&key);if(!stored)return pass();
 struct origin value=*stored;
 if(p.flags&1){value.pad|=2;bpf_map_update_elem(&origins,&key,&value,BPF_EXIST);}
 if(rewrite(skb,&p,&value,0)<0)return drop();
 /* Keep FIN mappings for retransmissions; a fresh SYN may reuse a closed tuple. */
 if(p.flags&4)bpf_map_delete_elem(&origins,&key);
 count(1);return TC_ACT_OK;
}
char LICENSE[] SEC("license")="GPL";
