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

/*
 *-----------------------------------------------------------------------------
 * Include Files
 *-----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*
 *-----------------------------------------------------------------------------
 * Private Defines
 *-----------------------------------------------------------------------------
 */

#define MIN_IP_HEADER_LENGTH  (5)
#define DEFAULT_TTL           (48)
#define SUPPORTED_IP_VERSION  (4)

/*
 *-----------------------------------------------------------------------------
 * Private Macros
 *-----------------------------------------------------------------------------
 */

#define GET_ETHERNET_PACKET_TYPE(pktPtr)  (ntohs(((sr_ethernet_hdr_t*)pktPtr)->ether_type))
#define GET_ETHERNET_DEST_ADDR(pktPtr)    (((sr_ethernet_hdr_t*)pktPtr)->ether_dhost)

#define LOG_MESSAGE(...) fprintf(stderr, __VA_ARGS__)

/*
 *-----------------------------------------------------------------------------
 * Private Types
 *-----------------------------------------------------------------------------
 */

/*
 *-----------------------------------------------------------------------------
 * Private variables & Constants
 *-----------------------------------------------------------------------------
 */

static uint16_t ipIdentifyNumber = 0;

static const uint8_t broadcastEthernetAddress[ETHER_ADDR_LEN] =
   { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*
 *-----------------------------------------------------------------------------
 * Private Function Declarations
 *-----------------------------------------------------------------------------
 */

static void linkHandleReceivedArpPacket(struct sr_instance* sr, sr_arp_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface);
static void linkArpAndSendPacket(struct sr_instance* sr, sr_ethernet_hdr_t* packet, 
   unsigned int length, const struct sr_if* const interface);
static void networkHandleReceivedIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface);
static void networkHandleIcmpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface);

/*
 *-----------------------------------------------------------------------------
 * Public Function Definitions
 *-----------------------------------------------------------------------------
 */

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

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int length,
   char* interface/* lent */)
{
   struct sr_if* receivedInterfaceEntry = NULL;
   
   /* REQUIRES */
   assert(sr);
   assert(packet);
   assert(interface);
   
   printf("*** -> Received packet of length %d \n", length);
   /* print_hdrs(packet, length); */
   
   /* fill in code here */
   
   if (length < sizeof(sr_ethernet_hdr_t))
   {
      /* Ummm...this packet doesn't appear to be long enough to 
       * process... Drop it like it's hot! */
      return;
   }
   
   receivedInterfaceEntry = sr_get_interface(sr, interface);
   
   if ((receivedInterfaceEntry == NULL)
      || ((memcmp(GET_ETHERNET_DEST_ADDR(packet), receivedInterfaceEntry->addr, ETHER_ADDR_LEN) != 0)
         && (memcmp(GET_ETHERNET_DEST_ADDR(packet), broadcastEthernetAddress, ETHER_ADDR_LEN) != 0)))
   {
      /* Packet not sent to our ethernet address? */
      return;
   }
   
   switch (ethertype(packet))
   {
      case ethertype_arp:
         /* Pass the packet to the next layer, strip the low level header. */
         linkHandleReceivedArpPacket(sr, (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)), 
            length - sizeof(sr_ethernet_hdr_t), receivedInterfaceEntry);
         break;
         
      case ethertype_ip:
         /* Pass the packet to the next layer, strip the low level header. */
         networkHandleReceivedIpPacket(sr, (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)), 
            length - sizeof(sr_ethernet_hdr_t), receivedInterfaceEntry);
         break;
         
      default:
         /* We have no logic to handle other packet types. Drop the packet! */
         return;
   }

}/* end sr_ForwardPacket */

/*
 *-----------------------------------------------------------------------------
 * Private Function Definitions
 *-----------------------------------------------------------------------------
 */

static void linkHandleReceivedArpPacket(struct sr_instance* sr, sr_arp_hdr_t * packet,
   unsigned int length, const struct sr_if* const interface)
{
   if (length < sizeof(sr_arp_hdr_t))
   {
      /* Not big enough to be an ARP packet... */
      return;
   }
   
   if ((ntohs(packet->ar_pro) != ethertype_ip) || (ntohs(packet->ar_hln) != arp_hrd_ethernet)
      || (packet->ar_pln != IP_ADDR_LEN) || (packet->ar_hln != ETHER_ADDR_LEN))
   {
      /* Received unsupported packet argument */
   }
   
   switch (ntohs(packet->ar_op))
   {
      case arp_op_request:
      {
         if (ntohl(packet->ar_tip) == interface->ip)
         {
            /* We're being ARPed! Prepare the reply! */
            uint8_t* replyPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)replyPacket;
            sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(replyPacket + sizeof(sr_ethernet_hdr_t));
            
            /* Ethernet Header */
            memcpy(ethernetHdr->ether_dhost, packet->ar_sha, ETHER_ADDR_LEN);
            memcpy(ethernetHdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
            ethernetHdr->ether_type = htons(ethertype_arp);
            
            /* ARP Header */
            arpHdr->ar_hrd = htons(arp_hrd_ethernet);
            arpHdr->ar_pro = htons(ethertype_ip);
            arpHdr->ar_hln = ETHER_ADDR_LEN;
            arpHdr->ar_pln = IP_ADDR_LEN;
            arpHdr->ar_op = htons(arp_op_reply);
            memcpy(arpHdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
            arpHdr->ar_sip = htonl(interface->ip);
            memcpy(arpHdr->ar_tha, packet->ar_sha, ETHER_ADDR_LEN);
            arpHdr->ar_tip = packet->ar_sip;
            
            sr_send_packet(sr, replyPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
               interface->name);
            
            /* We didn't start this ARP, but we'll take advantage of it. If 
             * this is not in our cache, add it and remove any pending 
             * requests as well. */
            sr_arpreq_destroy(&sr->cache,
               sr_arpcache_insert(&sr->cache, packet->ar_sha, ntohl(packet->ar_sip)));
            
            free(replyPacket);
         }
         break;
      }
      
      default:
      {
         /* Unrecognized ARP type */
         break;
      }
   }
}

static void networkHandleReceivedIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface)
{
   if (length < sizeof(sr_ip_hdr_t))
   {
      /* Not big enough to be an IP packet... */
      return;
   }
   
   /* Verify checksum before parsing packet. */
   /* We have two options here.
    * 1) always assume the packet header is 20 bytes long, precluding us 
    *    from receiving packets with option bytes set.
    * 2) We take the length field as gospel *i.e. there isn't an error in 
    *    this byte) and go with it. 
    * I will choose the latter, but protect against headers less than 20 
    * bytes.
    */
   if (packet->ip_hl >= MIN_IP_HEADER_LENGTH)
   {
      uint16_t headerChecksum = packet->ip_sum;
      uint16_t calculatedChecksum = 0;
      packet->ip_sum = 0;
      
      calculatedChecksum = cksum(packet, packet->ip_hl * 4);
      
      if (headerChecksum != calculatedChecksum)
      {
         /* Bad checksum... */
         return;
      }
   }
   else
   {
      /* Something is way wrong with this packet. Throw it out. */
      return;
   }
   
   if (packet->ip_v != SUPPORTED_IP_VERSION)
   {
      /* What do you think we are? A fancy, IPv6 router? Guess again! Process 
       * IPv4 packets only.*/
      return;
   }
   
   if (ntohl(packet->ip_dst) == interface->ip)
   {
      /* Somebody likes me, because they're sending packets to my address! */
      if (packet->ip_p == (uint8_t) ip_protocol_icmp)
      {
         networkHandleIcmpPacket(sr, packet, length, interface);
      }
      else
      {
         /* I don't process anything else! */
         /* TODO: port unreachable */
      }
   }
}

static void networkHandleIcmpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface)
{
   sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*) (((uint8_t*) packet) + (packet->ip_hl * 4));
   int icmpPayloadLength = length - (packet->ip_hl * 4) - sizeof(sr_icmp_hdr_t);
   
   if (icmpHeader->icmp_type == icmp_type_echo_request)
   {
      /* Send an echo Reply! */
      uint8_t* replyPacket = malloc(length + sizeof(sr_ethernet_hdr_t));
      sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
      sr_icmp_hdr_t* replyIcmpHeader = (sr_ip_hdr_t*) ((uint8_t*) replyIpHeader
         + sizeof(sr_ip_hdr_t));
      
      /* Fill in IP Header fields. */
      replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
      replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
      replyIpHeader->ip_tos = 0;
      replyIpHeader->ip_len = htons((uint16_t) length);
      replyIpHeader->ip_id = htons(ipIdentifyNumber); ipIdentifyNumber++;
      replyIpHeader->ip_off = IP_DF;
      replyIpHeader->ip_ttl = DEFAULT_TTL;
      replyIpHeader->ip_p = ip_protocol_icmp;
      replyIpHeader->ip_sum = 0;
      replyIpHeader->ip_src = packet->ip_dst; /* Already in network byte order. */
      replyIpHeader->ip_dst = packet->ip_src; /* Already in network byte order. */
      replyIpHeader->ip_sum = cksum(replyIpHeader, MIN_IP_HEADER_LENGTH * 4);
      
      /* Fill in ICMP fields. */
      replyIcmpHeader->icmp_type = icmp_type_echo_reply;
      replyIcmpHeader->icmp_code = 0;
      replyIcmpHeader->icmp_sum = 0;
      
      /* Copy the old payload into the new one... */
      memcpy(replyIcmpHeader + sizeof(sr_icmp_hdr_t), icmpHeader + sizeof(sr_icmp_hdr_t),
         icmpPayloadLength);
      
      /* ...then update the final checksum for the ICMP payload. */
      replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, icmpPayloadLength + sizeof(sr_icmp_hdr_t));
      
      /* Reply payload built. Ship it! */
      linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket, length + sizeof(sr_ethernet_hdr_t),
         interface);
      
      free(replyPacket);
   }
   else
   {
      /* I don't send any packets myself...How did I receive another ICMP type? */
      LOG_MESSAGE("Received unexpected ICMP message. Type: %u, Code: %u\n", 
         icmpHeader->icmp_type, icmpHeader->icmp_code);
   }
}

static void linkArpAndSendPacket(struct sr_instance* sr, sr_ethernet_hdr_t* packet, 
   unsigned int length, const struct sr_if* const interface)
{
   /* TODO: Fill in ethernet header */
   /* TODO: ARP! */
   packet->ether_type = htons(ethertype_ip);
   sr_send_packet(sr, (uint8_t*) packet, length, interface->name);
}
