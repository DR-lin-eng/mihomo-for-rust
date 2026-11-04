/* First-packet userspace classification, then native kernel forwarding.
 * GPL-3.0-or-later. No kernel-private structures or CO-RE dependencies. */
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct key { __u8 source[16], destination[16]; __u16 source_port,destination_port; __u32 family,protocol; };
struct value {
 struct bpf_spin_lock lock; __u32 active; __u64 id; __u8 target[16]; __u16 target_port,flags; __u32 padding;
 __u64 timeout_ns,last_seen_ns,upload,download;
 __u32 upload_ack,download_ack,upload_end,download_end,upload_fin,download_fin;
};
struct action { __u64 id; __u32 enabled,pad; };
struct pending_value { __u64 seen; __u32 interface,pad; };
struct fragment_key { __u8 source[16],destination[16]; __u32 identifier,family,protocol; };
struct fragment_value { struct key key; __u64 seen; __u32 reply,pad; };
struct parameters { __u32 mark,tun_index,enabled,pad; };
struct local_address { __u8 address[16]; __u32 family; };
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,1024); __type(key,struct local_address); __type(value,__u32); } direct_local SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct parameters); } direct_config SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4096); __type(key,struct key); __type(value,struct value); } direct_flows SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4096); __type(key,struct key); __type(value,struct action); } direct_actions SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,4096); __type(key,struct key); __type(value,struct key); } direct_replies SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,4096); __type(key,struct key); __type(value,struct pending_value); } direct_pending SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,8192); __type(key,struct fragment_key); __type(value,struct fragment_value); } direct_fragments SEC(".maps");
struct packet { struct key key; __u32 ip,l4,end,fragment_id; __u16 fragment,more; __u8 flags,pad; __u32 sequence,ack,payload; };

static __always_inline int parse_at(struct __sk_buff *skb,struct packet *p,__u32 ip) {
 p->ip=ip;__u8 version;if(bpf_skb_load_bytes(skb,ip,&version,1)<0)return -1;
 if((version>>4)==4){
  __u8 h[20];if(bpf_skb_load_bytes(skb,ip,h,20)<0||(h[0]&15)<5)return -1;
  __u16 n,f,id;__builtin_memcpy(&n,h+2,2);__builtin_memcpy(&id,h+4,2);__builtin_memcpy(&f,h+6,2);
  p->key.family=4;p->key.protocol=h[9];__builtin_memcpy(p->key.source,h+12,4);__builtin_memcpy(p->key.destination,h+16,4);
  p->l4=ip+(h[0]&15)*4;p->end=ip+bpf_ntohs(n);p->fragment=bpf_ntohs(f)&0x1fff;p->more=!!(bpf_ntohs(f)&0x2000);p->fragment_id=id;
 }else if((version>>4)==6){
  __u8 h[40];if(bpf_skb_load_bytes(skb,ip,h,40)<0)return -1;__u16 n;__builtin_memcpy(&n,h+4,2);
  p->key.family=6;p->key.protocol=h[6];__builtin_memcpy(p->key.source,h+8,16);__builtin_memcpy(p->key.destination,h+24,16);p->l4=ip+40;p->end=ip+40+bpf_ntohs(n);
  #pragma unroll
  for(int i=0;i<4;i++){
   if(p->key.protocol==0||p->key.protocol==43||p->key.protocol==60){__u8 e[2];if(bpf_skb_load_bytes(skb,p->l4,e,2)<0)return -1;p->key.protocol=e[0];p->l4+=((__u32)e[1]+1)*8;}
   else if(p->key.protocol==44){__u8 e[8];if(bpf_skb_load_bytes(skb,p->l4,e,8)<0)return -1;__u16 f;__builtin_memcpy(&f,e+2,2);p->fragment=bpf_ntohs(f)>>3;p->more=bpf_ntohs(f)&1;__builtin_memcpy(&p->fragment_id,e+4,4);p->key.protocol=e[0];p->l4+=8;}
  }
 }else return -1;
 if(p->l4>skb->len||p->end>skb->len||p->end<p->l4)return -1;
 if(p->key.protocol!=6&&p->key.protocol!=17)return 2;
 if(p->fragment)return 1;
 __u8 ports[4];if(bpf_skb_load_bytes(skb,p->l4,ports,4)<0)return -1;
 __builtin_memcpy(&p->key.source_port,ports,2);__builtin_memcpy(&p->key.destination_port,ports+2,2);
 if(p->key.protocol==6){
  __u8 h[20];if(bpf_skb_load_bytes(skb,p->l4,h,20)<0||(h[12]>>4)<5)return -1;
  __u32 seq,ack;__builtin_memcpy(&seq,h+4,4);__builtin_memcpy(&ack,h+8,4);p->sequence=bpf_ntohl(seq);p->ack=bpf_ntohl(ack);p->flags=h[13];
  __u32 offset=p->l4+(h[12]>>4)*4;if(offset>p->end)return -1;p->payload=p->end-offset;
 }else {__u16 n;if(bpf_skb_load_bytes(skb,p->l4+4,&n,2)<0||bpf_ntohs(n)<8)return -1;p->payload=bpf_ntohs(n)-8;}
 return 0;
}
static __always_inline int parse(struct __sk_buff *skb,struct packet *p,int l3){
 __u32 ip=0;if(!l3){__u16 proto;if(bpf_skb_load_bytes(skb,12,&proto,2)<0)return -1;ip=14;
  #pragma unroll
  for(int i=0;i<2;i++){if(proto==bpf_htons(ETH_P_8021Q)||proto==bpf_htons(ETH_P_8021AD)){if(bpf_skb_load_bytes(skb,ip+2,&proto,2)<0)return -1;ip+=4;}}
  if(proto!=bpf_htons(ETH_P_IP)&&proto!=bpf_htons(ETH_P_IPV6))return -1;
 }return parse_at(skb,p,ip);
}
static __always_inline struct key reverse(struct key k){
 struct key r={.source_port=k.destination_port,.destination_port=k.source_port,.family=k.family,.protocol=k.protocol};
 __builtin_memcpy(r.source,k.destination,16);__builtin_memcpy(r.destination,k.source,16);return r;
}
static __always_inline struct fragment_key fragkey(struct packet *p){
 struct fragment_key f={.identifier=p->fragment_id,.family=p->key.family,.protocol=p->key.protocol};
 __builtin_memcpy(f.source,p->key.source,16);__builtin_memcpy(f.destination,p->key.destination,16);return f;
}
static __always_inline int available(struct key *k,struct value *v,__u64 now){
 struct action *a=bpf_map_lookup_elem(&direct_actions,k);
 return a&&a->id==v->id&&a->enabled&&now-v->last_seen_ns<v->timeout_ns;
}
static __always_inline int after(__u32 a,__u32 b){return (__s32)(a-b)>0;}
static __always_inline void account(struct value *v,struct packet *p,int reply,__u64 now){
 bpf_spin_lock(&v->lock);v->last_seen_ns=now;
 if(p->key.protocol==17){if(reply)v->download+=p->payload;else v->upload+=p->payload;}
 else{
  __u32 initial=reply?2:1;
  if((p->flags&2)&&!(v->flags&initial)){
   v->flags|=initial;
   if(reply){v->download_ack=p->sequence+1;v->download_end=p->sequence+1;}
   else{v->upload_ack=p->sequence+1;v->upload_end=p->sequence+1;}
  }
  __u32 end=p->sequence+p->payload+!!(p->flags&2);
  if(reply){if(after(end,v->download_end))v->download_end=end;if(p->flags&1){v->download_fin=end;v->flags|=8;}}
  else{if(after(end,v->upload_end))v->upload_end=end;if(p->flags&1){v->upload_fin=end;v->flags|=4;}}
  if(p->flags&16){
   __u32 ack=p->ack;
   if(reply&&(v->flags&1)){if(after(ack,v->upload_end))ack=v->upload_end;if(after(ack,v->upload_ack)){v->upload+=(__u32)(ack-v->upload_ack);v->upload_ack=ack;}}
   else if(!reply&&(v->flags&2)){if(after(ack,v->download_end))ack=v->download_end;if(after(ack,v->download_ack)){v->download+=(__u32)(ack-v->download_ack);v->download_ack=ack;}}
  }
  if(p->flags&4)v->flags|=16;
 }
 bpf_spin_unlock(&v->lock);
}
static __always_inline int rewrite(struct __sk_buff *skb,struct packet *p,const __u8 *address,__u16 port,int destination){
 __u32 addr_off=p->ip+(p->key.family==4?(destination?16:12):(destination?24:8));
 __u32 port_off=p->l4+(destination?2:0),csum_off=p->l4+(p->key.protocol==6?16:6);
 __u16 checksum=0;if(!p->fragment&&bpf_skb_load_bytes(skb,csum_off,&checksum,2)<0)return -1;
 int l4=!p->fragment&&(p->key.protocol==6||checksum||p->key.family==6);
 #pragma unroll
 for(int i=0;i<4;i++){
  if(i==0||p->key.family==6){
   __u32 old,new;if(bpf_skb_load_bytes(skb,addr_off+i*4,&old,4)<0)return -1;__builtin_memcpy(&new,address+i*4,4);
   if(l4&&bpf_l4_csum_replace(skb,csum_off,old,new,BPF_F_PSEUDO_HDR|BPF_F_MARK_MANGLED_0|4)<0)return -1;
   if(p->key.family==4&&bpf_l3_csum_replace(skb,p->ip+10,old,new,4)<0)return -1;
   if(bpf_skb_store_bytes(skb,addr_off+i*4,&new,4,0)<0)return -1;
  }
 }
 if(!p->fragment){__u16 old;if(bpf_skb_load_bytes(skb,port_off,&old,2)<0)return -1;
  if(l4&&bpf_l4_csum_replace(skb,csum_off,old,port,BPF_F_MARK_MANGLED_0|2)<0)return -1;
  if(bpf_skb_store_bytes(skb,port_off,&port,2,0)<0)return -1;
 }return 0;
}
static __always_inline int forward(struct __sk_buff *skb,int l3){
 __u32 zero=0;struct parameters *cfg=bpf_map_lookup_elem(&direct_config,&zero);if(!cfg)return TC_ACT_OK;
 struct packet p={};int parsed=parse(skb,&p,l3);if(parsed<0||parsed==2)return TC_ACT_OK;
 __u64 now=bpf_ktime_get_ns();struct key key=p.key;
 struct fragment_key fk={};
 if(parsed==1){fk=fragkey(&p);struct fragment_value *f=bpf_map_lookup_elem(&direct_fragments,&fk);if(!f||f->reply||now-f->seen>30000000000ULL)return l3?TC_ACT_SHOT:bpf_redirect(cfg->tun_index,0);key=f->key;}
 if(!l3){struct local_address local={.family=p.key.family};__builtin_memcpy(local.address,p.key.destination,16);if(bpf_map_lookup_elem(&direct_local,&local))return TC_ACT_OK;
  if((p.key.family==4&&(p.key.destination[0]==0||p.key.destination[0]==127||p.key.destination[0]>=224))||(p.key.family==6&&p.key.destination[0]==255))return TC_ACT_OK;
 }
 struct value *v=bpf_map_lookup_elem(&direct_flows,&key);
 if(!l3&&parsed==0&&p.key.protocol==6&&(p.flags&0x12)==2)v=0;
 if(!v){
  if(l3)return TC_ACT_OK;
  if(!cfg->enabled)return TC_ACT_SHOT;
  struct pending_value pending={.seen=now,.interface=skb->ifindex};bpf_map_update_elem(&direct_pending,&key,&pending,BPF_ANY);
  return bpf_redirect(cfg->tun_index,0);
 }
 if(!available(&key,v,now)){
  if(!l3&&p.key.protocol==17){struct pending_value pending={.seen=now,.interface=skb->ifindex};bpf_map_update_elem(&direct_pending,&key,&pending,BPF_ANY);return bpf_redirect(cfg->tun_index,0);}
  return TC_ACT_SHOT;
 }
 if(parsed==0){account(v,&p,0,now);if(p.more){fk=fragkey(&p);struct fragment_value f={.key=key,.seen=now};bpf_map_update_elem(&direct_fragments,&fk,&f,BPF_ANY);}}
 if(rewrite(skb,&p,v->target,v->target_port,1)<0)return TC_ACT_SHOT;
 skb->mark=cfg->mark;return TC_ACT_OK;
}
SEC("classifier/direct_in") int mihomo_kd_in(struct __sk_buff *skb){return forward(skb,0);}
SEC("classifier/direct_tun") int mihomo_kd_tun(struct __sk_buff *skb){return forward(skb,1);}

static __always_inline int icmp_error(struct __sk_buff *skb,struct packet *outer){
 if((outer->key.family==4&&outer->key.protocol!=1)||(outer->key.family==6&&outer->key.protocol!=58))return TC_ACT_OK;
 __u8 type;if(bpf_skb_load_bytes(skb,outer->l4,&type,1)<0)return TC_ACT_OK;
 if((outer->key.family==4&&type!=3&&type!=11&&type!=12)||(outer->key.family==6&&(type<1||type>4)))return TC_ACT_OK;
 __u32 ip=outer->l4+8,l4=0;struct key real={};
 __u8 version;if(bpf_skb_load_bytes(skb,ip,&version,1)<0)return TC_ACT_OK;
 if((version>>4)==4){
  __u8 h[20];if(bpf_skb_load_bytes(skb,ip,h,20)<0||(h[0]&15)<5)return TC_ACT_OK;
  __u16 frag;__builtin_memcpy(&frag,h+6,2);if(bpf_ntohs(frag)&0x1fff)return TC_ACT_OK;
  real.family=4;real.protocol=h[9];__builtin_memcpy(real.source,h+12,4);__builtin_memcpy(real.destination,h+16,4);l4=ip+(h[0]&15)*4;
 }else if((version>>4)==6){
  __u8 h[40];if(bpf_skb_load_bytes(skb,ip,h,40)<0)return TC_ACT_OK;
  real.family=6;real.protocol=h[6];__builtin_memcpy(real.source,h+8,16);__builtin_memcpy(real.destination,h+24,16);l4=ip+40;
  #pragma unroll
  for(int i=0;i<4;i++) {if(real.protocol==0||real.protocol==43||real.protocol==60){__u8 e[2];if(bpf_skb_load_bytes(skb,l4,e,2)<0)return TC_ACT_OK;real.protocol=e[0];l4+=((__u32)e[1]+1)*8;}}
 }else return TC_ACT_OK;
 if(real.protocol!=6&&real.protocol!=17)return TC_ACT_OK;
 __u8 ports[4];if(bpf_skb_load_bytes(skb,l4,ports,4)<0)return TC_ACT_OK;
 __builtin_memcpy(&real.source_port,ports,2);__builtin_memcpy(&real.destination_port,ports+2,2);
 struct key *key=bpf_map_lookup_elem(&direct_replies,&real);if(!key)return TC_ACT_OK;
 struct value *v=bpf_map_lookup_elem(&direct_flows,key);if(!v||!available(key,v,bpf_ktime_get_ns()))return TC_ACT_SHOT;
 __u32 icmp_sum=outer->l4+2,addr=ip+(real.family==4?16:24),transport_sum=l4+(real.protocol==6?16:6);
 __u16 old_ip_sum=0,old_transport_sum=0;
 if(real.family==4&&bpf_skb_load_bytes(skb,ip+10,&old_ip_sum,2)<0)return TC_ACT_SHOT;
 int has_transport=bpf_skb_load_bytes(skb,transport_sum,&old_transport_sum,2)==0;
 #pragma unroll
 for(int i=0;i<4;i++) {if(i==0||real.family==6){
  __u32 old,new;if(bpf_skb_load_bytes(skb,addr+i*4,&old,4)<0)return TC_ACT_SHOT;__builtin_memcpy(&new,key->destination+i*4,4);
  if(bpf_l4_csum_replace(skb,icmp_sum,old,new,4)<0)return TC_ACT_SHOT;
  if(real.family==4&&bpf_l3_csum_replace(skb,ip+10,old,new,4)<0)return TC_ACT_SHOT;
  if(has_transport&&(real.protocol==6||old_transport_sum||real.family==6)&&bpf_l4_csum_replace(skb,transport_sum,old,new,BPF_F_PSEUDO_HDR|BPF_F_MARK_MANGLED_0|4)<0)return TC_ACT_SHOT;
  if(bpf_skb_store_bytes(skb,addr+i*4,&new,4,0)<0)return TC_ACT_SHOT;
 }}
 if(real.family==4){__u16 sum;if(bpf_skb_load_bytes(skb,ip+10,&sum,2)<0||bpf_l4_csum_replace(skb,icmp_sum,old_ip_sum,sum,2)<0)return TC_ACT_SHOT;}
 if(has_transport&&(real.protocol==6||old_transport_sum||real.family==6)){__u16 sum;if(bpf_skb_load_bytes(skb,transport_sum,&sum,2)<0||bpf_l4_csum_replace(skb,icmp_sum,old_transport_sum,sum,2)<0)return TC_ACT_SHOT;}
 return TC_ACT_OK;
}

SEC("classifier/direct_out") int mihomo_kd_out(struct __sk_buff *skb){
 struct packet p={};int parsed=parse(skb,&p,0);if(parsed<0)return TC_ACT_OK;if(parsed==2)return icmp_error(skb,&p);
 __u64 now=bpf_ktime_get_ns();struct key key={};struct fragment_key fk={};
 if(parsed==1){fk=fragkey(&p);struct fragment_value *f=bpf_map_lookup_elem(&direct_fragments,&fk);if(!f||!f->reply||now-f->seen>30000000000ULL)return TC_ACT_OK;key=f->key;}
 else{struct key real=reverse(p.key);struct key *original=bpf_map_lookup_elem(&direct_replies,&real);if(!original)return TC_ACT_OK;key=*original;}
 struct value *v=bpf_map_lookup_elem(&direct_flows,&key);if(!v)return TC_ACT_OK;
 if(!available(&key,v,now))return TC_ACT_SHOT;
 if(parsed==0){account(v,&p,1,now);if(p.more){fk=fragkey(&p);struct fragment_value f={.key=key,.seen=now,.reply=1};bpf_map_update_elem(&direct_fragments,&fk,&f,BPF_ANY);}}
 if(rewrite(skb,&p,key.destination,key.destination_port,0)<0)return TC_ACT_SHOT;
 return TC_ACT_OK;
}
char LICENSE[] SEC("license")="GPL";
