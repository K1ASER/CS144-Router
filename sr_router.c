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

#define GET_IP_HEADER_LENGTH(pktPtr)      ((((sr_ip_hdr_t*)(pktPtr))->ip_hl) * 4)

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
static void networkForwardIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const receivedInterface);

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
   
   /*printf("*** -> Received packet of length %d \n", length);
   print_hdrs(packet, length);*/
   
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
      LOG_MESSAGE("Dropping packet due to invalid Ethernet receive parameters.\n");
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
         LOG_MESSAGE("Dropping packet due to invalid Ethernet message type: 0x%X.\n", ethertype(packet));
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
   
   if ((ntohs(packet->ProtocolType) != ethertype_ip)
      || (ntohs(packet->HardwareType) != arp_hrd_ethernet)
      || (packet->ProtocolAddressLength != IP_ADDR_LEN) 
      || (packet->HardwareAddressLength != ETHER_ADDR_LEN))
   {
      /* Received unsupported packet argument */
      LOG_MESSAGE("ARP packet received with invalid parameters. Dropping.\n");
      return;
   }
   
   switch (ntohs(packet->OperationCode))
   {
      case arp_op_request:
      {
         if (packet->TargetIpAddress == interface->ip)
         {
            /* We're being ARPed! Prepare the reply! */
            uint8_t* replyPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)replyPacket;
            sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(replyPacket + sizeof(sr_ethernet_hdr_t));
            
            LOG_MESSAGE("Received ARP request. Sending ARP reply.\n");
            
            /* Ethernet Header */
            memcpy(ethernetHdr->ether_dhost, packet->SenderHardwareAddress, ETHER_ADDR_LEN);
            memcpy(ethernetHdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
            ethernetHdr->ether_type = htons(ethertype_arp);
            
            /* ARP Header */
            arpHdr->HardwareType = htons(arp_hrd_ethernet);
            arpHdr->ProtocolType = htons(ethertype_ip);
            arpHdr->HardwareAddressLength = ETHER_ADDR_LEN;
            arpHdr->ProtocolAddressLength = IP_ADDR_LEN;
            arpHdr->OperationCode = htons(arp_op_reply);
            memcpy(arpHdr->SenderHardwareAddress, interface->addr, ETHER_ADDR_LEN);
            arpHdr->SenderIpAddress = interface->ip;
            memcpy(arpHdr->TargetHardwareAddress, packet->SenderHardwareAddress, ETHER_ADDR_LEN);
            arpHdr->TargetIpAddress = packet->SenderIpAddress;
            
            sr_send_packet(sr, replyPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
               interface->name);
            
            free(replyPacket);
         }
         break;
      }
      
      case arp_op_reply:
      {
         if (packet->TargetIpAddress == interface->ip)
         {
            struct sr_arpreq* requestPointer = sr_arpcache_insert(
               &sr->cache, packet->SenderHardwareAddress, ntohl(packet->SenderIpAddress));
            
            if (requestPointer != NULL)
            {
               LOG_MESSAGE("Received ARP reply, sending all queued packets.\n");
               while (requestPointer->packets != NULL)
               {
                  struct sr_packet* curr = requestPointer->packets;
                  
                  /* Copy in the newly discovered Ethernet address of the frame */
                  memcpy(((sr_ethernet_hdr_t*) curr->buf)->ether_dhost,
                     packet->SenderHardwareAddress, ETHER_ADDR_LEN);
                  
                  /* The last piece of the pie is now complete. Ship it. */
                  sr_send_packet(sr, curr->buf, curr->len, curr->iface);
                  
                  /* Forward list of packets. */
                  requestPointer->packets = requestPointer->packets->next;
                  
                  /* Free all memory associated with this packet (allocated on queue). */
                  free(curr->buf);
                  free(curr->iface);
                  free(curr);
               }
               
               /* Bye bye ARP request. */
               sr_arpreq_destroy(&sr->cache, requestPointer);
            }
            else
            {
               LOG_MESSAGE("Received ARP reply, but found no request.\n");
            }
         }
         break;
      }
      
      default:
      {
         /* Unrecognized ARP type */
         LOG_MESSAGE("Received packet with invalid ARP type: 0x%X.\n", ntohs(packet->OperationCode));
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
      LOG_MESSAGE("Received IP packet with invalid length. Dropping.\n");
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
      
      calculatedChecksum = cksum(packet, GET_IP_HEADER_LENGTH(packet));
      
      if (headerChecksum != calculatedChecksum)
      {
         /* Bad checksum... */
         LOG_MESSAGE("IP checksum failed. Dropping received packet.\n");
         return;
      }
   }
   else
   {
      /* Something is way wrong with this packet. Throw it out. */
      LOG_MESSAGE("Received IP packet with invalid length in header. Dropping.\n");
      return;
   }
   
   if (packet->ip_v != SUPPORTED_IP_VERSION)
   {
      /* What do you think we are? A fancy, IPv6 router? Guess again! Process 
       * IPv4 packets only.*/
      LOG_MESSAGE("Received non-IPv4 packet. Dropping.\n");
      return;
   }
   
   if (packet->ip_dst == interface->ip)
   {
      /* Somebody must like me, because they're sending packets to my 
       * address! */
      if (packet->ip_p == (uint8_t) ip_protocol_icmp)
      {
         networkHandleIcmpPacket(sr, packet, length, interface);
      }
      else
      {
         /* I don't process anything else! Send port unreachable */
         uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
            + sizeof(sr_icmp_t3_hdr_t));
         sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
         sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
            + sizeof(sr_ip_hdr_t));
         
         LOG_MESSAGE("Received non-ICMP echo packet. Sending ICMP port unreachable.\n");
         
         /* Fill in IP header */
         replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
         replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
         replyIpHeader->ip_tos = 0;
         replyIpHeader->ip_len = htons((uint16_t) length);
         replyIpHeader->ip_id = htons(ipIdentifyNumber); ipIdentifyNumber++;
         replyIpHeader->ip_off = IP_DF;
         replyIpHeader->ip_ttl = DEFAULT_TTL;
         replyIpHeader->ip_p = ip_protocol_icmp;
         replyIpHeader->ip_sum = 0;
         replyIpHeader->ip_src = interface->ip;
         replyIpHeader->ip_dst = packet->ip_src; /* Already in network byte order. */
         replyIpHeader->ip_sum = cksum(replyIpHeader, GET_IP_HEADER_LENGTH(replyIpHeader));
         
         /* Fill in ICMP fields. */
         replyIcmpHeader->icmp_type = icmp_type_desination_unreachable;
         replyIcmpHeader->icmp_code = icmp_code_destination_port_unreachable;
         replyIcmpHeader->icmp_sum = 0;
         memcpy(replyIcmpHeader->data, packet, ICMP_DATA_SIZE);
         replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
         
         linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket,
            sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
         
         free(replyPacket);
      }
   }
   else
   {
      /* Decrement TTL and forward. */
      packet->ip_ttl -= 1;
      if (packet->ip_ttl == 0)
      {
         /* Uh oh... someone's just about run out of time. */
         uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
            + sizeof(sr_icmp_t3_hdr_t));
         sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
         sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
            + sizeof(sr_ip_hdr_t));
         
         LOG_MESSAGE("TTL expired on received packet. Sending an ICMP time exceeded.\n");
         
         /* Fill in IP header */
         replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
         replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
         replyIpHeader->ip_tos = 0;
         replyIpHeader->ip_len = htons((uint16_t) length);
         replyIpHeader->ip_id = htons(ipIdentifyNumber); ipIdentifyNumber++;
         replyIpHeader->ip_off = IP_DF;
         replyIpHeader->ip_ttl = DEFAULT_TTL;
         replyIpHeader->ip_p = ip_protocol_icmp;
         replyIpHeader->ip_sum = 0;
         replyIpHeader->ip_src = interface->ip;
         replyIpHeader->ip_dst = packet->ip_src; /* Already in network byte order. */
         replyIpHeader->ip_sum = cksum(replyIpHeader, GET_IP_HEADER_LENGTH(replyIpHeader));
         
         /* Fill in ICMP fields. */
         replyIcmpHeader->icmp_type = icmp_type_time_exceeded;
         replyIcmpHeader->icmp_code = 0;
         replyIcmpHeader->icmp_sum = 0;
         memcpy(replyIcmpHeader->data, packet, ICMP_DATA_SIZE);
         replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
         
         linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket,
            sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
         
         free(replyPacket);
      }
      else
      {
         /* Recalculate checksum since we altered the packet header. */
         packet->ip_sum = 0;
         packet->ip_sum = cksum(packet, GET_IP_HEADER_LENGTH(packet));
         
         networkForwardIpPacket(sr, packet, length, interface);
      }
   }
}

static void networkHandleIcmpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const interface)
{
   sr_icmp_hdr_t* icmpHeader = (sr_icmp_hdr_t*) (((uint8_t*) packet) + GET_IP_HEADER_LENGTH(packet));
   int icmpLength = length - GET_IP_HEADER_LENGTH(packet);
   
   /* Check the integrity of the ICMP packet */
   {
      uint16_t headerChecksum = icmpHeader->icmp_sum;
      uint16_t calculatedChecksum = 0;
      icmpHeader->icmp_sum = 0;
      
      calculatedChecksum = cksum(icmpHeader, icmpLength);
      
      if (headerChecksum != calculatedChecksum)
      {
         /* Bad checksum... */
         LOG_MESSAGE("ICMP checksum failed. Dropping received packet.\n");
         return;
      }
   }
   
   if (icmpHeader->icmp_type == icmp_type_echo_request)
   {
      /* Send an echo Reply! */
      uint8_t* replyPacket = malloc(icmpLength + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
      sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
      sr_icmp_hdr_t* replyIcmpHeader = (sr_icmp_hdr_t*) ((uint8_t*) replyIpHeader
         + sizeof(sr_ip_hdr_t));
      assert(replyPacket);
      
      LOG_MESSAGE("Received ICMP echo request packet. Sending ICMP echo reply.\n");
      
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
      replyIpHeader->ip_sum = cksum(replyIpHeader, GET_IP_HEADER_LENGTH(replyIpHeader));
      
      /* Fill in ICMP fields. */
      replyIcmpHeader->icmp_type = icmp_type_echo_reply;
      replyIcmpHeader->icmp_code = 0;
      replyIcmpHeader->icmp_sum = 0;
      
      /* Copy the old payload into the new one... */
      memcpy(((uint8_t*) replyIcmpHeader) + sizeof(sr_icmp_hdr_t),
         ((uint8_t*) icmpHeader) + sizeof(sr_icmp_hdr_t), icmpLength - sizeof(sr_icmp_hdr_t));
      
      /* ...then update the final checksum for the ICMP payload. */
      replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, icmpLength);
      
      /* Reply payload built. Ship it! */
      linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket, length + sizeof(sr_ethernet_hdr_t),
         interface);
      
      free(replyPacket);
   }
   else
   {
      /* I don't send any non-ICMP packets...How did I receive another ICMP type? */
      LOG_MESSAGE("Received unexpected ICMP message. Type: %u, Code: %u\n", 
         icmpHeader->icmp_type, icmpHeader->icmp_code);
   }
}

static void networkForwardIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const receivedInterface)
{
   uint32_t destinationIpAddress = ntohl(packet->ip_dst);
   struct sr_rt* forwardRoute = NULL;
   struct sr_rt* routeIter;
   
   for (routeIter = sr->routing_table; routeIter; routeIter = routeIter->next)
   {
      if ((destinationIpAddress & routeIter->mask.s_addr) 
         == (ntohl(routeIter->dest.s_addr) & routeIter->mask.s_addr))
      {
         /* Prefix match. */
         /*TODO: Assumes the default route is the first entry. */
         forwardRoute = routeIter;
      }
   }
   
   /* If we made the decision to forward onto the interface we received the 
    * packet, something is wrong. Send a host unreachable if this is the case. */
   if ((forwardRoute != NULL) && (strcmp(forwardRoute->interface, receivedInterface->name) != 0))
   {
      /* We found a viable route. Forward to it! */
      struct sr_if* forwardInterface = sr_get_interface(sr, forwardRoute->interface);
      uint8_t* forwardPacket = malloc(length + sizeof(sr_ethernet_hdr_t));
      memcpy(forwardPacket + sizeof(sr_ethernet_hdr_t), packet, length);
      
      LOG_MESSAGE("Forwarding from interface %s to %s\n", receivedInterface->name, 
         forwardInterface->name);
   
      linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*)forwardPacket,
         length + sizeof(sr_ethernet_hdr_t), forwardInterface);
   }
   else
   {
      /* Routing table told us to route this packet back the way it came. 
       * That's probably wrong, so we assume the host is actually 
       * unreachable. */
      uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
         + sizeof(sr_icmp_t3_hdr_t));
      sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
      sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
         + sizeof(sr_ip_hdr_t));
      
      LOG_MESSAGE("Routing decision could not be made. Sending ICMP Host unreachable.\n");
      
      /* Fill in IP header */
      replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
      replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
      replyIpHeader->ip_tos = 0;
      replyIpHeader->ip_len = htons(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
      replyIpHeader->ip_id = htons(ipIdentifyNumber); ipIdentifyNumber++;
      replyIpHeader->ip_off = IP_DF;
      replyIpHeader->ip_ttl = DEFAULT_TTL;
      replyIpHeader->ip_p = ip_protocol_icmp;
      replyIpHeader->ip_sum = 0;
      replyIpHeader->ip_src = receivedInterface->ip;
      replyIpHeader->ip_dst = packet->ip_src; /* Already in network byte order. */
      replyIpHeader->ip_sum = cksum(replyIpHeader, GET_IP_HEADER_LENGTH(replyIpHeader));
      
      /* Fill in ICMP fields. */
      replyIcmpHeader->icmp_type = icmp_type_desination_unreachable;
      replyIcmpHeader->icmp_code = icmp_code_destination_host_unreachable;
      replyIcmpHeader->icmp_sum = 0;
      memcpy(replyIcmpHeader->data, packet, ICMP_DATA_SIZE);
      replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
      
      linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket,
         sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), receivedInterface);
      
      free(replyPacket);
      
   }
}

/**
 * linkArpAndSendPacket()\n
 * IP Stack Level: Link Layer (Ethernet)\n
 * Description:\n
 *    Function provided the link layer functionality required to send a 
 *    provided packet.  If there is an ARP cache entry for the destination, 
 *    the packet is sent immediately.  Otherwise the function will send an 
 *    ARP request along the provided interface.
 * @brief Function populates Ethernet header of a provided packet and sends it on the provided interface.
 * @param sr pointer to simple router state.
 * @param packet pointer to packet to send.
 * @param length size of the packet.
 * @param interface pointer to interface to send packet on.
 * @warning Function is for IP datagrams only. ARP packets should not go through this function.
 */
static void linkArpAndSendPacket(struct sr_instance* sr, sr_ethernet_hdr_t* packet, 
   unsigned int length, const struct sr_if* const interface)
{
   /* Need the gateway IP to do the ARP cache lookup. */
   uint32_t nextHopIpAddress = ntohl(sr_get_rt(sr, interface->name)->gw.s_addr);
   struct sr_arpentry* arpEntry = sr_arpcache_lookup(&sr->cache, nextHopIpAddress);
   
   /* This function is only for ip packets, fill in the type */
   packet->ether_type = htons(ethertype_ip);
   memcpy(packet->ether_shost, interface->addr, ETHER_ADDR_LEN);
   
   if (arpEntry != NULL)
   {
      memcpy(packet->ether_dhost, arpEntry->mac, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t*) packet, length, interface->name);
   }
   else
   {
      /* We need to ARP our next hop. Setup the request and send the ARP packet. */
      struct sr_arpreq* arpRequestPtr = sr_arpcache_queuereq(&sr->cache, nextHopIpAddress,
         (uint8_t*) packet, length, interface->name);
      
      arpRequestPtr->requestedInterface = interface;
      arpRequestPtr->requestingInterface = NULL;
      
      LinkSendArpRequest(sr, arpRequestPtr);
      
      arpRequestPtr->times_sent = 1;
      arpRequestPtr->sent = time(NULL);
   }
}

/**
 * LinkSendArpRequest()\n
 * IP Stack Level: Link Layer (Ethernet)\n
 * @brief Function sends an ARP request based on the provided request.
 * @param sr pointer to simple router state.
 * @param request pointer ARP request state.
 * @post does NOT update times sent in request. Must be done by caller.
 */
void LinkSendArpRequest(struct sr_instance* sr, struct sr_arpreq* request)
{
   uint8_t* arpPacket = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
   sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*) arpPacket;
   sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*) (arpPacket + sizeof(sr_ethernet_hdr_t));
   assert(arpPacket);
   
   LOG_MESSAGE("ARPing %u.%u.%u.%u on %s\n", (request->ip >> 24) & 0xFF, 
      (request->ip >> 16) & 0xFF, (request->ip >> 8) & 0xFF, request->ip & 0xFF, 
      request->requestedInterface->name);
   
   /* Ethernet Header */
   memcpy(ethernetHdr->ether_dhost, broadcastEthernetAddress, ETHER_ADDR_LEN);
   memcpy(ethernetHdr->ether_shost, request->requestedInterface->addr, ETHER_ADDR_LEN);
   ethernetHdr->ether_type = htons(ethertype_arp);
   
   /* ARP Header */
   arpHdr->HardwareType = htons(arp_hrd_ethernet);
   arpHdr->ProtocolType = htons(ethertype_ip);
   arpHdr->HardwareAddressLength = ETHER_ADDR_LEN;
   arpHdr->ProtocolAddressLength = IP_ADDR_LEN;
   arpHdr->OperationCode = htons(arp_op_request);
   memcpy(arpHdr->SenderHardwareAddress, request->requestedInterface->addr, ETHER_ADDR_LEN);
   arpHdr->SenderIpAddress = request->requestedInterface->ip;
   memset(arpHdr->TargetHardwareAddress, 0, ETHER_ADDR_LEN); /* Not strictly necessary by RFC 826 */
   arpHdr->TargetIpAddress = htonl(request->ip);
   
   sr_send_packet(sr, arpPacket, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),
      request->requestedInterface->name);
   
   free(arpPacket);
}

void NetworkSendIcmpPacket(struct sr_instance* sr, sr_icmp_type_t icmpType, sr_icmp_code_t icmpCode,
   sr_ip_hdr_t* originalPacketPtr, const struct sr_if* interface)
{
   uint8_t* replyPacket = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) 
      + sizeof(sr_icmp_t3_hdr_t));
   sr_ip_hdr_t* replyIpHeader = (sr_ip_hdr_t*) (replyPacket + sizeof(sr_ethernet_hdr_t));
   sr_icmp_t3_hdr_t* replyIcmpHeader = (sr_icmp_t3_hdr_t*) ((uint8_t*) replyIpHeader
      + sizeof(sr_ip_hdr_t));
   
   LOG_MESSAGE("Router instructed to send ICMP packet.\n");
   
   /* Fill in IP header */
   replyIpHeader->ip_v = SUPPORTED_IP_VERSION;
   replyIpHeader->ip_hl = MIN_IP_HEADER_LENGTH;
   replyIpHeader->ip_tos = 0;
   replyIpHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
   replyIpHeader->ip_id = htons(ipIdentifyNumber); ipIdentifyNumber++;
   replyIpHeader->ip_off = IP_DF;
   replyIpHeader->ip_ttl = DEFAULT_TTL;
   replyIpHeader->ip_p = ip_protocol_icmp;
   replyIpHeader->ip_sum = 0;
   replyIpHeader->ip_src = interface->ip;
   replyIpHeader->ip_dst = originalPacketPtr->ip_src; /* Already in network byte order. */
   replyIpHeader->ip_sum = cksum(replyIpHeader, GET_IP_HEADER_LENGTH(replyIpHeader));
   
   /* Fill in ICMP fields. */
   replyIcmpHeader->icmp_type = icmp_type_desination_unreachable;
   replyIcmpHeader->icmp_code = icmp_code_destination_host_unreachable;
   replyIcmpHeader->icmp_sum = 0;
   memcpy(replyIcmpHeader->data, originalPacketPtr, ICMP_DATA_SIZE);
   replyIcmpHeader->icmp_sum = cksum(replyIcmpHeader, sizeof(sr_icmp_t3_hdr_t));
   
   linkArpAndSendPacket(sr, (sr_ethernet_hdr_t*) replyPacket,
      sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface);
   
   free(replyPacket);
}
