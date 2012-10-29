#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include <cstring>

extern "C"
{
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
}

#define NUM_INTERFACES (3)

const uint8_t ethernetOneAddr[ETHER_ADDR_LEN] = { 0x76, 0xfb, 0x5e, 0xa7, 0x04, 0x87 };
const uint8_t ethernetTwoAddr[ETHER_ADDR_LEN] = { 0xfa, 0xa4, 0x0c, 0x89, 0xd7, 0xdc };
const uint8_t ethernetThreeAddr[ETHER_ADDR_LEN] = { 0x0e, 0x20, 0xab, 0x92, 0xe8, 0xb1 };

const uint8_t broadcastEthernetAddr[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
const uint8_t internetEthernetAddr[ETHER_ADDR_LEN] = { 0x0E, 0x20, 0xAB, 0x80, 0x00, 0x02 };

const uint32_t interfaceOneIpAddr = 0x6B177371; /* 107.23.115.113 */
const uint32_t interfaceOneDest = 0x6B177383; /* 107.23.115.131 */
const uint32_t interfaceOneGateway = 0x6B177383; /* 107.23.115.131 */
const uint32_t interfaceOneMask = 0xFFFFFFFF;

const uint32_t interfaceTwoIpAddr = 0x6B177379; /* 107.23.115.121 */
const uint32_t interfaceTwoDest = 0x6B177213; /* 107.23.114.19 */
const uint32_t interfaceTwoGateway = 0x6B177213; /* 107.23.114.19 */
const uint32_t interfaceTwoMask = 0xFFFFFFFF;

const uint32_t interfaceThreeIpAddr = 0x0A00010B; /* 10.0.1.11 */
const uint32_t interfaceThreeDest = 0; /* 0.0.0.0 */
const uint32_t interfaceThreeGateway = 0x0A000101; /* 10.0.1.1 */
const uint32_t interfaceThreeMask = 0; /* 0.0.0.0 */

const uint32_t myIpAddress = 0x40791424;


int sr_send_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, 
   const char* interface)
{
   if (length < sizeof(sr_ethernet_hdr_t))
   {
      FAIL("Send Packet called with an invalid packet length.");
   }
   
   if (ethertype(packet) == ethertype_arp)
   {
      sr_arp_hdr_t* arpPacket = (sr_arp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
      mock().actualCall("SendPacket")
         .withParameter("sr", sr)
         .withParameter("Length", (int) length)
         .withParameter("Interface", interface)
         .withParameter("EthernetProtocol", ethertype_arp)
         .withParameter("HardwareType", (int) ntohs(arpPacket->ar_hrd));
   }
   else if (ethertype(packet) == ethertype_ip)
   {
      sr_ip_hdr_t* ipHeader = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));
      if (ipHeader->ip_p == ip_protocol_icmp)
      {
         sr_icmp_hdr_t* icmpHeader =
            (sr_icmp_hdr_t*) (((uint8_t*) ipHeader) + (ipHeader->ip_hl * 4));
         mock().actualCall("SendPacket")
            .withParameter("sr", sr)
            .withParameter("Length", (int)length)
            .withParameter("Interface", interface)
            .withParameter("EthernetProtocol", ethertype_ip)
            .withParameter("InternetProtocol", ip_protocol_icmp)
            .withParameter("SourceAddress", (int) ntohl(ipHeader->ip_src))
            .withParameter("DestinationAddress", (int) ntohl(ipHeader->ip_dst))
            .withParameter("IcmpType", icmpHeader->icmp_type);
      }
      else
      {
         mock().actualCall("SendPacket")
            .withParameter("sr", sr)
            .withParameter("Length", (int)length)
            .withParameter("Interface", interface)
            .withParameter("EthernetProtocol", ethertype_ip)
            .withParameter("SourceAddress", (int) ntohl(ipHeader->ip_src))
            .withParameter("DestinationAddress", (int) ntohl(ipHeader->ip_dst));
      }
   }
   else
   {
      mock().actualCall("SendPacket")
         .withParameter("sr", sr)
         .withParameter("Length", (int) length)
         .withParameter("Interface", interface)
         .withParameter("EthernetProtocol", (int) ethertype(packet));
   }
   return 0;
}

TEST_GROUP(LabThreeTests)
{
   void setup()
   {
      struct sr_if* tempInterface;
      struct sr_rt* tempRoutingEntry;
      
      testSimpleRouterState = (struct sr_instance*) malloc(sizeof(struct sr_instance));
      CHECK(testSimpleRouterState);
      
      /* Add the three router interfaces */
      tempInterface = (struct sr_if*) malloc(sizeof(struct sr_if));
      CHECK(tempInterface);
      strcpy(tempInterface->name, "eth3");
      memcpy(tempInterface->addr, ethernetThreeAddr, ETHER_ADDR_LEN);
      tempInterface->ip = interfaceThreeIpAddr;
      testSimpleRouterState->if_list = tempInterface;
      
      tempInterface = (struct sr_if*) malloc(sizeof(struct sr_if));
      CHECK(tempInterface);
      strcpy(tempInterface->name, "eth2");
      memcpy(tempInterface->addr, ethernetTwoAddr, ETHER_ADDR_LEN);
      tempInterface->ip = interfaceTwoIpAddr;
      testSimpleRouterState->if_list->next = tempInterface;
      
      tempInterface = (struct sr_if*) malloc(sizeof(struct sr_if));
      CHECK(tempInterface);
      strcpy(tempInterface->name, "eth1");
      memcpy(tempInterface->addr, ethernetOneAddr, ETHER_ADDR_LEN);
      tempInterface->ip = interfaceOneIpAddr;
      tempInterface->next = NULL;
      testSimpleRouterState->if_list->next->next = tempInterface;
      
      /* Add the three router interfaces */
      tempRoutingEntry = (struct sr_rt*) malloc(sizeof(struct sr_rt));
      CHECK(tempRoutingEntry);
      tempRoutingEntry->dest = { interfaceThreeDest };
      tempRoutingEntry->gw = { interfaceThreeGateway };
      tempRoutingEntry->mask = { interfaceThreeMask };
      strcpy(tempRoutingEntry->interface, "eth3");
      testSimpleRouterState->routing_table = tempRoutingEntry;
      
      tempRoutingEntry = (struct sr_rt*) malloc(sizeof(struct sr_rt));
      CHECK(tempRoutingEntry);
      tempRoutingEntry->dest = { interfaceOneDest };
      tempRoutingEntry->gw = { interfaceOneGateway };
      tempRoutingEntry->mask = { interfaceOneMask };
      strcpy(tempRoutingEntry->interface, "eth1");
      testSimpleRouterState->routing_table->next = tempRoutingEntry;
      
      tempRoutingEntry = (struct sr_rt*) malloc(sizeof(struct sr_rt));
      CHECK(tempRoutingEntry);
      tempRoutingEntry->dest = { interfaceTwoDest };
      tempRoutingEntry->gw = { interfaceTwoGateway };
      tempRoutingEntry->mask = { interfaceTwoMask };
      strcpy(tempRoutingEntry->interface, "eth2");
      tempRoutingEntry->next = NULL;
      testSimpleRouterState->routing_table->next->next = tempRoutingEntry;
      
      sr_init(testSimpleRouterState);
   }
   
   void teardown()
   {
      free(testSimpleRouterState->if_list->next->next);
      free(testSimpleRouterState->if_list->next);
      free(testSimpleRouterState->if_list);
      
      free(testSimpleRouterState->routing_table->next->next);
      free(testSimpleRouterState->routing_table->next);
      free(testSimpleRouterState->routing_table);
      
      free(testSimpleRouterState);
      
      mock().checkExpectations();
      mock().clear();
   }
   
   struct sr_instance* testSimpleRouterState;
};

TEST(LabThreeTests, HandlesArpRequest)
{
   /* Send an ARP request from the Internet next hop router. */
   uint8_t* packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
   sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)packet;
   sr_arp_hdr_t* arpHdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
   
   /* Ethernet Header */
   memcpy(ethernetHdr->ether_dhost, broadcastEthernetAddr, ETHER_ADDR_LEN);
   memcpy(ethernetHdr->ether_shost, internetEthernetAddr, ETHER_ADDR_LEN);
   ethernetHdr->ether_type = htons(ethertype_arp);
   
   /* ARP Header */
   arpHdr->ar_hrd = htons(arp_hrd_ethernet);
   arpHdr->ar_pro = htons(ethertype_ip);
   arpHdr->ar_hln = ETHER_ADDR_LEN;
   arpHdr->ar_pln = IP_ADDR_LEN;
   arpHdr->ar_op = htons(arp_op_request);
   memcpy(arpHdr->ar_sha, internetEthernetAddr, ETHER_ADDR_LEN);
   arpHdr->ar_sip = htonl(interfaceThreeGateway);
   memset(arpHdr->ar_tha, 0x00, ETHER_ADDR_LEN);
   arpHdr->ar_tip = htonl(interfaceThreeIpAddr);
   
   mock().expectOneCall("SendPacket")
      .withParameter("sr", this->testSimpleRouterState)
      .withParameter("Length", (int)(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
      .withParameter("Interface", "eth3")
      .withParameter("EthernetProtocol", ethertype_arp).ignoreOtherParameters();
   
   sr_handlepacket(this->testSimpleRouterState, packet,
      (unsigned int)(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)), (char*)"eth3");
   
   free(packet);
}

TEST(LabThreeTests, HandlesPingToRouter)
{
   const uint8_t pingPayloadBytes = 56;
   const uint8_t ipPacketLength = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) 
      + sizeof(sr_icmp_echo_hdr_t) + pingPayloadBytes - 1;
   
   /* Send an ICMP echo request from the Internet next hop router. */
   uint8_t* packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + ipPacketLength);
   sr_ethernet_hdr_t* ethernetHdr = (sr_ethernet_hdr_t*)packet;
   sr_ip_hdr_t* ipHdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
   sr_icmp_hdr_t* icmpHdr = (sr_icmp_hdr_t*) (((uint8_t*) ipHdr) + sizeof(sr_ip_hdr_t));
   sr_icmp_echo_hdr_t* echoHdr = (sr_icmp_echo_hdr_t*) (((uint8_t*) icmpHdr) + sizeof(sr_icmp_hdr_t));
   
   /* Ethernet Header */
   memcpy(ethernetHdr->ether_dhost, ethernetThreeAddr, ETHER_ADDR_LEN);
   memcpy(ethernetHdr->ether_shost, internetEthernetAddr, ETHER_ADDR_LEN);
   ethernetHdr->ether_type = htons(ethertype_ip);
   
   /* IP Header */
   ipHdr->ip_v = 4;
   ipHdr->ip_hl = 5;
   ipHdr->ip_tos = 0;
   ipHdr->ip_len = ipPacketLength;
   ipHdr->ip_id = 0;
   ipHdr->ip_off = IP_DF;
   ipHdr->ip_ttl = 58;
   ipHdr->ip_p = ip_protocol_icmp;
   ipHdr->ip_sum = 0;
   ipHdr->ip_src = htonl(myIpAddress);
   ipHdr->ip_dst = htonl(interfaceThreeIpAddr);
   ipHdr->ip_sum = cksum(ipHdr, sizeof(sr_ip_hdr_t));
   
   /* ICMP Header */
   icmpHdr->icmp_type = (uint8_t)icmp_type_echo_request;
   icmpHdr->icmp_code = 0;
   icmpHdr->icmp_sum = 0;
   
   /* Echo Payload */
   echoHdr->identifier = 0;
   echoHdr->sequenceNumber = 1;
   for (int i = 0; i < pingPayloadBytes; i++)
   {
      /* Linux style ping payload */
      echoHdr->data[i] = i;
   }
   
   /* Fill in the ICMP checksum */
   icmpHdr->icmp_sum = cksum(icmpHdr, ipPacketLength - sizeof(sr_ip_hdr_t));
   
   mock().expectOneCall("SendPacket")
      .withParameter("DestinationAddress", (int) myIpAddress)
      .withParameter("InternetProtocol", ip_protocol_icmp)
      .withParameter("IcmpType", icmp_type_echo_reply)
      .ignoreOtherParameters();
   
   sr_handlepacket(this->testSimpleRouterState, packet, sizeof(sr_ethernet_hdr_t) + ipPacketLength,
      (char *) "eth3");
   
   free(packet);
}

