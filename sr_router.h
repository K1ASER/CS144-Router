/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdbool.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"
#include "sr_rt.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

typedef struct sr_instance
{
   int sockfd; /* socket to server */
   char user[32]; /* user name */
   char host[32]; /* host name */
   char template_name[30]; /* template name if any */
   unsigned short topo_id;
   struct sockaddr_in sr_addr; /* address to server */
   struct sr_if* if_list; /* list of interfaces */
   struct sr_rt* routing_table; /* routing table */
   struct sr_arpcache cache; /* ARP cache */
   pthread_attr_t attr;
   FILE* logfile;
   struct sr_nat* nat; /**< Pointer to NAT state structure. */
} sr_instance_t;

/**
 * getIpHeaderLength()\n
 * IP Stack Level: Network Layer (IP)\n
 * @brief Gets the length (in bytes) of an IP datagram.
 * @param pktPtr pointer packet IP header.
 * @return size of datagram (in bytes).
 */
static inline uint16_t getIpHeaderLength(sr_ip_hdr_t const * const pktPtr)
{
   return (pktPtr->ip_hl) * 4;
}

static inline sr_icmp_hdr_t * getIcmpHeaderFromIpHeader(sr_ip_hdr_t * packetPtr)
{
   return (sr_icmp_hdr_t*) (((uint8_t*) packetPtr) + getIpHeaderLength(packetPtr));
}

static inline sr_tcp_hdr_t * getTcpHeaderFromIpHeader(sr_ip_hdr_t * packetPtr)
{
   return (sr_tcp_hdr_t*) (((uint8_t*) packetPtr) + getIpHeaderLength(packetPtr));
}

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance*, uint8_t*, unsigned int, const char*);
int sr_connect_to_server(struct sr_instance*, unsigned short, char*);
int sr_read_from_server(struct sr_instance*);

/* -- sr_router.c -- */
void sr_init(struct sr_instance*);
void sr_handlepacket(struct sr_instance*, uint8_t *, unsigned int, char*);
void LinkSendArpRequest(struct sr_instance* sr, struct sr_arpreq* request);
void IpSendTypeThreeIcmpPacket(struct sr_instance* sr, sr_icmp_code_t icmpCode,
   sr_ip_hdr_t* originalPacketPtr);
void IpHandleReceivedPacketToUs(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, sr_if_t const * const interface);
sr_rt_t* IpGetPacketRoute(struct sr_instance* sr, in_addr_t destIp);
void IpForwardIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet, unsigned int length,
   const struct sr_if* const receivedInterface);
bool IpDestinationIsUs(struct sr_instance* sr, const sr_ip_hdr_t* const packet);
bool IcmpPerformIntegrityCheck(sr_icmp_hdr_t * const icmpPacket, unsigned int length);
bool TcpPerformIntegrityCheck(sr_ip_hdr_t * const tcpPacket, unsigned int length);

/* -- sr_nat.c -- */
void NatHandleRecievedIpPacket(sr_instance_t*, sr_ip_hdr_t*, unsigned int, sr_if_t const * const);
void NatUndoPacketMapping(sr_instance_t*, sr_ip_hdr_t*, unsigned int, sr_if_t const * const);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance*, const char*);
void sr_set_ether_ip(struct sr_instance*, uint32_t);
void sr_set_ether_addr(struct sr_instance*, const unsigned char*);
void sr_print_if_list(struct sr_instance*);

#endif /* SR_ROUTER_H */
