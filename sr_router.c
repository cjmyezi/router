/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

 /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to process ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);
  /* handling ip header*/
  if (ethtype == ethertype_ip) { 
    fprintf(stderr, "Start to handle ip request\n");
    handle_ip(sr,packet,len,interface);
  }

  /* handling ARP msgs*/
  else if (ethtype == ethertype_arp) {
    fprintf(stderr, "call handle arp\n");
    handle_arp(sr,packet,len,interface);
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}/* end sr_ForwardPacket */

void handle_arp(struct sr_instance *sr, uint8_t * pckt, unsigned int len, char * interface){
  fprintf(stderr, "Start to handle arp request\n");
  int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    if (len < minlength)
      fprintf(stderr, "Failed to process ARP header, insufficient length\n");
    else
    {
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (pckt + sizeof(sr_ethernet_hdr_t));
        struct sr_arpentry *arp_entry;
        struct sr_arpreq *arp_req;
        struct sr_if* interf;

        interf = sr_get_interface(sr,interface);

        arp_entry = sr_arpcache_lookup(&sr->cache, arp_hdr->ar_sip);


        if (arp_entry != 0)
          free(arp_entry);
        else
        {
          arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha,arp_hdr->ar_sip);
          if (arp_req !=0)
          {
            struct sr_packet * pkt;
            for (pkt = arp_req->packets; pkt!=NULL;pkt = pkt->next){
              memcpy(((sr_ethernet_hdr_t *) (pkt->buf))->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
			  sr_send_packet(sr,pkt->buf,pkt->len,pkt->iface);
            }
            sr_arpreq_destroy(&sr->cache, arp_req);
          }
        }

        if(interf->ip == arp_hdr->ar_tip && ntohs(arp_hdr->ar_op) == arp_op_request)
        {
          /*fprintf(stderr, "Call reply arp\n");*/
          reply_arp(sr,arp_hdr,interface);
        }
    }
}


void reply_arp(struct sr_instance *sr, sr_arp_hdr_t * arp_hdr, char * interface){
    sr_arp_hdr_t * arp_reply = malloc(sizeof(sr_arp_hdr_t));

    struct sr_if *interf;

    interf = sr_get_interface(sr, interface);

    arp_reply->ar_hrd = htons(arp_hrd_ethernet);
    arp_reply->ar_pro = htons(ethertype_ip);
    arp_reply->ar_hln = ETHER_ADDR_LEN;
    arp_reply->ar_pln = 4; 
    arp_reply->ar_op = htons(arp_op_reply);
    memcpy(arp_reply->ar_sha, interf->addr, ETHER_ADDR_LEN);
    memcpy(arp_reply->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    arp_reply->ar_sip = arp_hdr->ar_tip;
    arp_reply->ar_tip = arp_hdr->ar_sip;

    struct sr_ethernet_hdr eth_hdr;
    eth_hdr.ether_type = htons(ethertype_arp);
    memcpy(eth_hdr.ether_dhost,arp_hdr->ar_sha,ETHER_ADDR_LEN);
    memcpy(eth_hdr.ether_shost,interf->addr,ETHER_ADDR_LEN);

    int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * pckt = malloc(len);
    memcpy(pckt, &eth_hdr,sizeof(eth_hdr));
    memcpy(pckt+sizeof(eth_hdr), arp_reply,sizeof(sr_arp_hdr_t));
    int err = sr_send_packet(sr,pckt,len,interface);
    if (err == -1)
      fprintf(stderr,"error sending arp reply packet\n");

    free(arp_reply);
    free(pckt);
}

void handle_ip(struct sr_instance *sr, uint8_t * pckt, unsigned int len, char* interface)
{
  sr_ip_hdr_t *ip_hdr;

  ip_hdr = (sr_ip_hdr_t *)(pckt + sizeof(sr_ethernet_hdr_t));
  uint16_t r_cksm = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  uint16_t e_cksm = cksum(ip_hdr, ip_hdr->ip_hl*4);

  if (len < sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t) || len != sizeof(sr_ethernet_hdr_t) + htons(ip_hdr->ip_len))
  {
    fprintf(stderr, "Failed to handle IP packet, Incorrect length\n");
    return;
  }

  if (r_cksm != e_cksm)
  {
    fprintf(stderr, "Incorrect checksum\n");
    return;
  }
  ip_hdr->ip_sum = e_cksm;

  struct sr_if * iter_if = sr->if_list;
  int flag = 0;

  while(iter_if!=NULL && flag == 0)
  {
    if (iter_if->ip == ip_hdr->ip_dst)
      flag = 1;
    iter_if = iter_if->next;
  }

  if (flag)
  {
    if(ip_hdr->ip_p == ip_protocol_icmp)
    {
      handle_icmp(sr,ip_hdr, len);
    }
    else if (ip_hdr->ip_p == 6 || ip_hdr->ip_p == 17)
    {
      send_icmp_packets(sr,3,3,ip_hdr,len);
    }
    else
    {
      fprintf(stderr, "drop it 1\n");
      return;
    }
  }
  else
  {
    if (ip_hdr->ip_ttl == 1)
    {
      fprintf(stderr, "identified as ttl reaches\n");
      send_icmp_packets(sr,11,0,ip_hdr,len);
    }
    else
    {
      fprintf(stderr, "forward\n");
      forward_packet(sr,ip_hdr,len);
    }
  }
}

void handle_icmp(struct sr_instance *sr, sr_ip_hdr_t * ip_hdr, unsigned int len)
{
    sr_icmp_hdr_t * icmp = (sr_icmp_hdr_t *) ((uint8_t *) ip_hdr + ip_hdr->ip_hl*4);
    unsigned int icmp_len = len -  ip_hdr->ip_hl*4 - sizeof(sr_ethernet_hdr_t);
    if (icmp->icmp_type == 8 && icmp->icmp_code == 0)
    {
      uint16_t r_cksm = icmp->icmp_sum;
      icmp->icmp_sum = 0;
      uint16_t e_cksm = cksum(icmp, icmp_len);
      if (r_cksm == e_cksm)
        send_icmp_packets(sr, 0, 0, ip_hdr, len);
      else
      {
        fprintf(stderr, "Invalid ICMP echo request.\n");
        return;
      }
    }

}

void handle_arp_req(struct sr_instance *sr, struct sr_arpreq * arp_req)
{
    sr_arp_hdr_t * arp_msg = malloc(sizeof(sr_arp_hdr_t));
		

		
    struct sr_if *interf;

    struct sr_rt *rt = find_longest_prefix_ip(sr, arp_req->ip);
    if (!rt)
    {
      fprintf(stderr, "Failed to obtain forwarding ip address in routing table. \n");
      return;
    }
  

    interf = sr_get_interface(sr, arp_req->packets->iface);

    arp_msg->ar_hrd = htons(arp_hrd_ethernet);
    arp_msg->ar_pro = htons(ethertype_ip);
    arp_msg->ar_hln = ETHER_ADDR_LEN;
    arp_msg->ar_pln = 4; 
    arp_msg->ar_op = htons(arp_op_request);
    memcpy(arp_msg->ar_sha, interf->addr, ETHER_ADDR_LEN);
    memset(arp_msg->ar_tha, 0xff , ETHER_ADDR_LEN);
    arp_msg->ar_sip = interf->ip;
    arp_msg->ar_tip = arp_req->ip;

    struct sr_ethernet_hdr eth_hdr;
    eth_hdr.ether_type = htons(ethertype_arp);
    memcpy(eth_hdr.ether_dhost,arp_msg->ar_tha,ETHER_ADDR_LEN);
    memcpy(eth_hdr.ether_shost,arp_msg->ar_sha,ETHER_ADDR_LEN);

    unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t * pckt = malloc(len);
    memcpy(pckt, &eth_hdr,sizeof(eth_hdr));
    memcpy(pckt+sizeof(eth_hdr), arp_msg,sizeof(sr_arp_hdr_t));
    int err = sr_send_packet(sr,pckt,len,interf->name);
    if (err == -1)
      fprintf(stderr,"error sending arp request packet\n");

    free(arp_msg);
    free(pckt);
}

struct sr_rt* find_longest_prefix_ip(struct sr_instance * sr, uint32_t ip)
{
  struct sr_rt* rt;
  uint32_t best_len = 0;
  struct sr_rt * best = NULL;

  for (rt = sr->routing_table; rt != NULL; rt = rt->next)
  {
    uint32_t prefix = (uint32_t) rt->mask.s_addr & ip;
    if (prefix == (uint32_t)rt->dest.s_addr)
    {
      if (prefix >= best_len)
      {
        best_len = rt->mask.s_addr;
        best = rt;
      }
    }
  

  }
  return best;
}

void send_icmp_packets(struct sr_instance * sr, uint8_t type, uint8_t code, sr_ip_hdr_t * ip_hdr, unsigned int len)
{
  unsigned int icmp_len;

  if (type == 0) /*echo reply*/
  {
    unsigned int total_len = len-sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t * pkt = malloc(total_len);
	memcpy(pkt, ip_hdr, total_len);

	pkt->ip_src = ip_hdr->ip_dst;
	pkt->ip_dst = ip_hdr->ip_src;

	sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *)((uint8_t *)pkt + ip_hdr->ip_hl*4);

    icmp_len = total_len -  ip_hdr->ip_hl*4;
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
	pkt->ip_sum = 0;
    pkt->ip_sum = cksum(pkt, ip_hdr->ip_hl*4);
	icmp_hdr->icmp_sum = cksum(icmp_hdr,icmp_len);
    send_ip_packet(sr, pkt, total_len);
    free(pkt);
  }
  else if (type == 3 || type == 11) /*unreachable or time exceeded*/
  {
	sr_icmp_t3_hdr_t * icmp_hdr;
    icmp_hdr = malloc(sizeof(sr_icmp_t3_hdr_t));
    unsigned int copy_len = len < 28 ? len:28;
	memcpy(&icmp_hdr->data, ip_hdr, copy_len);
    icmp_len = sizeof(sr_icmp_t3_hdr_t);
	icmp_hdr->unused =0;

	icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;

	icmp_hdr->icmp_sum = cksum(icmp_hdr,icmp_len);

	unsigned int total_len = sizeof(sr_ip_hdr_t) + icmp_len;
    sr_ip_hdr_t * pkt = malloc(total_len);
    pkt->ip_hl = 5;
    pkt->ip_v = 4;
    pkt->ip_tos = 0;
    pkt->ip_len = htons(total_len);
    pkt->ip_id = ip_hdr->ip_id;
    pkt->ip_off = htons(0x4000);
    pkt->ip_ttl = 255;
    pkt->ip_p = ip_protocol_icmp;
    pkt->ip_dst = ip_hdr->ip_src;
    pkt->ip_sum = 0;
	struct sr_rt * rt;
	rt = find_longest_prefix_ip(sr, ip_hdr->ip_src);
    struct sr_if * interf = sr_get_interface(sr, (char *)rt->interface);
    if(!interf)
    {
      /*fprintf(stderr, "Empty interface list, unable to send icmp message\n");*/
      free(icmp_hdr);
      free(pkt);
      return;
    }
    pkt->ip_src = interf->ip;
    memcpy((uint8_t *) pkt+pkt->ip_hl*4, icmp_hdr, icmp_len);
    pkt->ip_sum = cksum(pkt,pkt->ip_hl * 4);
    send_ip_packet(sr, pkt, total_len);
    free(icmp_hdr);
    free(pkt);
  }
}

void send_ip_packet(struct sr_instance * sr, sr_ip_hdr_t * ip_pkt, unsigned int len)
{
  /*fprintf(stderr, "send ip packets\n");*/

  struct sr_rt *rt = find_longest_prefix_ip(sr,ip_pkt->ip_dst);
  if (!rt)
  {
    /*fprintf(stderr, "entry not found\n");*/
      send_icmp_packets(sr, 3, 1, ip_pkt, len);
    return;
  }

  struct sr_if * interf = sr_get_interface(sr, rt->interface);

  unsigned int total_len = sizeof(sr_ethernet_hdr_t) + len;
  sr_ethernet_hdr_t * eth_p = malloc(total_len);
  memcpy((uint8_t *) eth_p + sizeof(sr_ethernet_hdr_t), ip_pkt, len);

  eth_p->ether_type = htons(ethertype_ip);
  memcpy(eth_p->ether_shost, interf->addr, ETHER_ADDR_LEN);

  struct sr_arpentry * entry = sr_arpcache_lookup(&(sr->cache), (uint32_t)rt->gw.s_addr);
  if (entry)
  {
    memcpy(eth_p->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    int err = sr_send_packet(sr, (uint8_t *) eth_p, total_len, interf->name);
    if (err == -1)
      fprintf(stderr, "Failure to send out ip packet\n");
    free(entry);
  }
  else
  {
    struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, (uint32_t)rt->gw.s_addr, (uint8_t *)eth_p, total_len, interf->name);
    arp_req_sender(sr,req);

  }

}

void forward_packet(struct sr_instance * sr, sr_ip_hdr_t * ip_hdr, unsigned int len)
{
  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
  send_ip_packet(sr, ip_hdr, len);
}