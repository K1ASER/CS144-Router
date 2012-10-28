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
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define GET_ETHERNET_PACKET_TYPE(pktPtr)  (ntohs(((sr_ethernet_hdr_t*)pktPtr)->ether_type))
#define GET_ETHERNET_DEST_ADDR(pktPtr)    (((sr_ethernet_hdr_t*)pktPtr)->ether_dhost)

static const uint8_t broadcastEthernetAddress[ETHER_ADDR_LEN] = 
   { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static void handleReceivedArpPacket();
static void handleReceivedIpPacket();

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

void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len,
   char* interface/* lent */)
{
   /* REQUIRES */
   assert(sr);
   assert(packet);
   assert(interface);
   
   /* TODO: Hack to see what interface is */
   interface[ETHER_ADDR_LEN] = '\0';
   
   printf("*** -> Received packet of length %d on interface %s\n", len, interface);
   print_hdrs(packet, len);
   
   /* fill in code here */
   
   if (len < sizeof(sr_ethernet_hdr_t))
   {
      /* Ummm...this packet doesn't appear to be long enough to 
       * process... Drop it like it's hot! */
      return;
   }
   
   if ((memcmp(GET_ETHERNET_DEST_ADDR(packet), interface, ETHER_ADDR_LEN) != 0)
      && (memcmp(GET_ETHERNET_DEST_ADDR(packet), broadcastEthernetAddress, ETHER_ADDR_LEN) != 0))
   {
      /* Packet not intended for us? */
   }
   
   switch (GET_ETHERNET_PACKET_TYPE(packet))
   {
      case ethertype_arp:
         handleReceivedArpPacket();
         break;
         
      case ethertype_ip:
         handleReceivedIpPacket();
         break;
         
      default:
         /* We have no logic to handle other packet types. Drop the packet! */
         return;
   }

}/* end sr_ForwardPacket */

static void handleReceivedArpPacket(void)
{
   
}

static void handleReceivedIpPacket(void)
{
   
}

