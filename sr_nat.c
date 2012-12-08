#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_nat.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"

#ifdef DONT_DEFINE_UNLESS_DEBUGGING
# define LOG_MESSAGE(...) fprintf(stderr, __VA_ARGS__)
#else 
# define LOG_MESSAGE(...)
#endif

#define SIM_OPEN_INBOUND_TIMEOUT    (6)

typedef enum
{
   NAT_PACKET_INBOUND,
   NAT_PACKET_OUTBOUND,
   NAT_PACKET_FOR_ROUTER,
   NAT_PACKET_DEFLECTION,
   NAT_PACKET_DROP
} NatDestinationResult_t;

static const char internalInterfaceName[] = "eth1";

/**
 * getInternalInterface()\n
 * Description:\n
 *    From assignment web page: For this assignment, interface "eth1" will 
 *    always be the internal interface and all other interfaces will always 
 *    be external interfaces.
 * @brief Returns the interface pointer for the internal NAT interface.
 * @param sr pointer to simple router state structure.
 * @return pointer to the internal router interface. 
 */
static inline sr_if_t* getInternalInterface(sr_instance_t *sr)
{
   return sr_get_interface(sr, internalInterfaceName);
}

static void sr_nat_destroy_mapping(sr_nat_t* nat, sr_nat_mapping_t* natMapping);
static void sr_nat_destroy_connection(sr_nat_mapping_t* natMapping, sr_nat_connection_t* connection);

static void natHandleReceivedOutboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet, 
   unsigned int length, const struct sr_if* const receivedInterface, sr_nat_mapping_t * natMapping);
static void natHandleReceivedInboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet, 
   unsigned int length, const struct sr_if* const receivedInterface, sr_nat_mapping_t * natMapping);
static NatDestinationResult_t natPacketDestination(sr_instance_t * sr, 
   sr_ip_hdr_t * const packet, unsigned int length, sr_if_t const * const receivedInterface, 
   sr_nat_mapping_t * associatedMapping);

static void natHandleTcpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
   sr_if_t const * const receivedInterface);
static void natHandleIcmpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
   sr_if_t const * const receivedInterface);

static sr_nat_mapping_t * natTrustedLookupInternal(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type);
static sr_nat_mapping_t * natTrustedLookupExternal(sr_nat_t * nat, uint16_t aux_ext,
   sr_nat_mapping_type type);
static sr_nat_mapping_t * natTrustedCreateMapping(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type);
static sr_nat_connection_t * natTrustedFindConnection(sr_nat_mapping_t *natEntry, uint32_t ip_ext, 
   uint16_t port_ext);

static void natRecalculateTcpChecksum(sr_ip_hdr_t * tcpPacket, unsigned int length);

int sr_nat_init(struct sr_nat *nat)
{ /* Initializes the nat */
   
   assert(nat);
   
   /* Acquire mutex lock */
   pthread_mutexattr_init(&(nat->attr));
   pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
   int success = pthread_mutex_init(&(nat->lock), &(nat->attr));
   
   /* Initialize timeout thread */

   pthread_attr_init(&(nat->thread_attr));
   pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
   pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
   pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
   pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);
   
   /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

   nat->mappings = NULL;
   /* Initialize any variables here */
   
   nat->nextIcmpIdentNumber = STARTING_PORT_NUMBER;
   nat->nextTcpPortNumber = STARTING_PORT_NUMBER;

   return success;
}

int sr_nat_destroy(struct sr_nat *nat)
{ /* Destroys the nat (free memory) */
   
   pthread_mutex_lock(&(nat->lock));
   
   /* free nat memory here */

   pthread_kill(nat->thread, SIGKILL);
   return pthread_mutex_destroy(&(nat->lock)) && pthread_mutexattr_destroy(&(nat->attr));
   
}

void *sr_nat_timeout(void *nat_ptr)
{ /* Periodic Timout handling */
   struct sr_nat *nat = (struct sr_nat *) nat_ptr;
   while (1)
   {
      sleep(1.0);
      pthread_mutex_lock(&(nat->lock));
      
      /* handle periodic tasks here */
      
      time_t curtime = time(NULL);
      sr_nat_mapping_t *mappingWalker = nat->mappings;
      
      while (mappingWalker)
      {
         switch (mappingWalker->type)
         {
            case nat_mapping_icmp:
               if (difftime(curtime, mappingWalker->last_updated) > nat->icmpTimeout)
               {
                  sr_nat_mapping_t* next = mappingWalker->next;
                  LOG_MESSAGE("ICMP mapping %u.%u.%u.%u:%u <-> %u timed out.\n",
                     (ntohl(mappingWalker->ip_int) >> 24) & 0xFF, 
                     (ntohl(mappingWalker->ip_int) >> 16) & 0xFF,
                     (ntohl(mappingWalker->ip_int) >> 8) & 0xFF, 
                     ntohl(mappingWalker->ip_int) & 0xFF,
                     ntohs(mappingWalker->aux_int), ntohs(mappingWalker->aux_ext));
                  sr_nat_destroy_mapping(nat, mappingWalker);
                  mappingWalker = next;
               }
               else
               {
                  mappingWalker = mappingWalker->next;
               }
               break;
               
            case nat_mapping_tcp:
            {
               sr_nat_connection_t * connectionIterator = mappingWalker->conns;
               while (connectionIterator)
               {
                  if ((connectionIterator->connectionState == nat_conn_connected)
                     && (difftime(curtime, connectionIterator->lastAccessed) > nat->tcpEstablishedTimeout))
                  {
                     sr_nat_connection_t* next = connectionIterator->next;
                     LOG_MESSAGE("Open TCP connection from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u deemed idle.\n",
                        (ntohl(mappingWalker->ip_int) >> 24) & 0xFF,
                        (ntohl(mappingWalker->ip_int) >> 16) & 0xFF,
                        (ntohl(mappingWalker->ip_int) >> 8) & 0xFF,
                        ntohl(mappingWalker->ip_int) & 0xFF, ntohs(mappingWalker->aux_int),
                        (ntohl(connectionIterator->external.ipAddress) >> 24) & 0xFF,
                        (ntohl(connectionIterator->external.ipAddress) >> 16) & 0xFF,
                        (ntohl(connectionIterator->external.ipAddress) >> 8) & 0xFF,
                        ntohl(connectionIterator->external.ipAddress) & 0xFF,
                        ntohs(connectionIterator->external.portNumber));
                     sr_nat_destroy_connection(mappingWalker, connectionIterator);
                     connectionIterator = next;
                  }
                  else if (((connectionIterator->connectionState == nat_conn_outbound_syn)
                        || (connectionIterator->connectionState == nat_conn_time_wait))
                     && (difftime(curtime, connectionIterator->lastAccessed) > nat->tcpTransitoryTimeout))
                  {
                     sr_nat_connection_t* next = connectionIterator->next;
                     LOG_MESSAGE("Transitory TCP connection from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u deemed idle.\n",
                        (ntohl(mappingWalker->ip_int) >> 24) & 0xFF,
                        (ntohl(mappingWalker->ip_int) >> 16) & 0xFF,
                        (ntohl(mappingWalker->ip_int) >> 8) & 0xFF,
                        ntohl(mappingWalker->ip_int) & 0xFF, ntohs(mappingWalker->aux_int),
                        (ntohl(connectionIterator->external.ipAddress) >> 24) & 0xFF,
                        (ntohl(connectionIterator->external.ipAddress) >> 16) & 0xFF,
                        (ntohl(connectionIterator->external.ipAddress) >> 8) & 0xFF,
                        ntohl(connectionIterator->external.ipAddress) & 0xFF,
                        ntohs(connectionIterator->external.portNumber));
                     sr_nat_destroy_connection(mappingWalker, connectionIterator);
                     connectionIterator = next;
                  }
                  else if ((connectionIterator->connectionState == nat_conn_inbound_syn_pending)
                     && (difftime(curtime, connectionIterator->lastAccessed) > nat->tcpTransitoryTimeout))
                  {
                     sr_nat_connection_t* next = connectionIterator->next;
                     LOG_MESSAGE("Pending TCP simultaneous open from %u.%u.%u.%u:%u to %u.%u.%u.%u:%u deemed invalid.\n",
                        (ntohl(mappingWalker->ip_int) >> 24) & 0xFF,
                        (ntohl(mappingWalker->ip_int) >> 16) & 0xFF,
                        (ntohl(mappingWalker->ip_int) >> 8) & 0xFF,
                        ntohl(mappingWalker->ip_int) & 0xFF, ntohs(mappingWalker->aux_int),
                        (ntohl(connectionIterator->external.ipAddress) >> 24) & 0xFF,
                        (ntohl(connectionIterator->external.ipAddress) >> 16) & 0xFF,
                        (ntohl(connectionIterator->external.ipAddress) >> 8) & 0xFF,
                        ntohl(connectionIterator->external.ipAddress) & 0xFF,
                        ntohs(connectionIterator->external.portNumber));
                     if (connectionIterator->queuedInboundSyn)
                     {
                        IpSendTypeThreeIcmpPacket(nat->routerState,
                           icmp_code_destination_port_unreachable,
                           connectionIterator->queuedInboundSyn);
                     }
                     sr_nat_destroy_connection(mappingWalker, connectionIterator);
                     connectionIterator = next;
                  }
                  else
                  {
                     connectionIterator = connectionIterator->next;
                  }
               }
               
               if (mappingWalker->conns == NULL)
               {
                  sr_nat_mapping_t* next = mappingWalker->next;
                  LOG_MESSAGE("No more active TCP connections on %u.%u.%u.%u:%u <-> %u. Closing.\n",
                     (ntohl(mappingWalker->ip_int) >> 24) & 0xFF, 
                     (ntohl(mappingWalker->ip_int) >> 16) & 0xFF,
                     (ntohl(mappingWalker->ip_int) >> 8) & 0xFF, 
                     ntohl(mappingWalker->ip_int) & 0xFF,
                     ntohs(mappingWalker->aux_int), ntohs(mappingWalker->aux_ext));
                  sr_nat_destroy_mapping(nat, mappingWalker);
                  mappingWalker = next;
               }
               else
               {
                  mappingWalker = mappingWalker->next;
               }
               
               break;
            }
               
            default:
               mappingWalker = mappingWalker->next;
               break;
         }
      }

      pthread_mutex_unlock(&(nat->lock));
   }
   return NULL;
}

/* Get the mapping associated with given external port.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat, uint16_t aux_ext,
   sr_nat_mapping_type type)
{
   pthread_mutex_lock(&(nat->lock));
   
   /* handle lookup here, malloc and assign to copy */
   sr_nat_mapping_t *copy = NULL;
   sr_nat_mapping_t *lookupResult = natTrustedLookupExternal(nat, aux_ext, type); 
   
   if (lookupResult != NULL)
   {
      lookupResult->last_updated = time(NULL);
      copy = malloc(sizeof(sr_nat_mapping_t));
      memcpy(copy, lookupResult, sizeof(sr_nat_mapping_t));
   }
   
   pthread_mutex_unlock(&(nat->lock));
   return copy;
}

static sr_nat_mapping_t * natTrustedLookupExternal(sr_nat_t * nat, uint16_t aux_ext,
   sr_nat_mapping_type type)
{
   for (sr_nat_mapping_t * mappingWalker = nat->mappings; mappingWalker != NULL ; mappingWalker =
      mappingWalker->next)
   {
      if ((mappingWalker->type == type) && (mappingWalker->aux_ext == aux_ext))
      {
         return mappingWalker;
      }
   }
   return NULL;
}

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   pthread_mutex_lock(&(nat->lock));
   
   /* handle lookup here, malloc and assign to copy. */
   struct sr_nat_mapping *copy = NULL;
   sr_nat_mapping_t * lookupResult = natTrustedLookupInternal(nat, ip_int, aux_int, type);
      
   if (lookupResult != NULL)
   {
      lookupResult->last_updated = time(NULL);
      copy = malloc(sizeof(sr_nat_mapping_t));
      assert(copy);
      memcpy(copy, lookupResult, sizeof(sr_nat_mapping_t));
   }
   
   pthread_mutex_unlock(&(nat->lock));
   return copy;
}

static sr_nat_mapping_t * natTrustedLookupInternal(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   sr_nat_mapping_t *mappingWalker;
      
   for (mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
   {
      if ((mappingWalker->type == type) && (mappingWalker->ip_int == ip_int)
         && (mappingWalker->aux_int == aux_int))
      {
         return mappingWalker;
      }
   }
   
   return NULL;
}

/* Insert a new mapping into the nat's mapping table.
 Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   pthread_mutex_lock(&(nat->lock));
   
   /* handle insert here, create a mapping, and then return a copy of it */
   struct sr_nat_mapping *mapping = natTrustedCreateMapping(nat, ip_int, aux_int, type);
   struct sr_nat_mapping *copy = malloc(sizeof(sr_nat_mapping_t));
   
   if (type == nat_mapping_icmp)
   {
      LOG_MESSAGE("Created new ICMP mapping %u.%u.%u.%u:%u <-> %u.\n", 
         (ntohl(ip_int) >> 24) & 0xFF, (ntohl(ip_int) >> 16) & 0xFF, 
         (ntohl(ip_int) >> 8) & 0xFF, ntohl(ip_int) & 0xFF, 
         ntohs(aux_int), ntohs(mapping->aux_ext));
   }
   else if (type == nat_mapping_tcp)
   {
      LOG_MESSAGE("Created new TCP mapping %u.%u.%u.%u:%u <-> %u.\n", 
         (ntohl(ip_int) >> 24) & 0xFF, (ntohl(ip_int) >> 16) & 0xFF, 
         (ntohl(ip_int) >> 8) & 0xFF, ntohl(ip_int) & 0xFF, 
         ntohs(aux_int), ntohs(mapping->aux_ext));
   }
   
   memcpy(copy, mapping, sizeof(sr_nat_mapping_t));
   
   pthread_mutex_unlock(&(nat->lock));
   return copy;
}

static sr_nat_mapping_t * natTrustedCreateMapping(sr_nat_t *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   struct sr_nat_mapping *mapping = malloc(sizeof(sr_nat_mapping_t));
   
   if (type == nat_mapping_icmp)
   {
      mapping->aux_ext = htons(nat->nextIcmpIdentNumber);
      mapping->conns = NULL;
      if (++nat->nextIcmpIdentNumber > LAST_PORT_NUMBER)
      {
         /* TODO: Point of improvement. We should really check if the port 
          * currently has a mapping.  It is assumed for the sake of this project 
          * it is assumed 10,000 connections are enough for the life of the 
          * router program. */
         nat->nextIcmpIdentNumber = STARTING_PORT_NUMBER;
      }
   }
   else if (type == nat_mapping_tcp)
   {
      mapping->aux_ext = htons(nat->nextTcpPortNumber);
      mapping->conns = NULL;
      if (++nat->nextTcpPortNumber > LAST_PORT_NUMBER)
      {
         /* TODO: Point of improvement. We should really check if the port 
          * currently has a mapping.  It is assumed for the sake of this project 
          * it is assumed 10,000 connections are enough for the life of the 
          * router program. */
         nat->nextTcpPortNumber = STARTING_PORT_NUMBER;
      }
   }
   
   /* Store mapping information */
   mapping->aux_int = aux_int;
   mapping->ip_int = ip_int;
   mapping->last_updated = time(NULL);
   mapping->type = type;
   
   /* Add mapping to the front of the list. */
   mapping->next = nat->mappings;
   nat->mappings = mapping;
   
   return mapping;
}

/**
 * sr_nat_destroy_mapping()\n
 * @brief removes a mapping from the linked list. Based off of ARP cache implementation.
 * @param nat pointer to NAT structure.
 * @param natMapping mapping to remove from list.
 * @warning Assumes that NAT structure is already locked!
 */
static void sr_nat_destroy_mapping(sr_nat_t* nat, sr_nat_mapping_t* natMapping)
{
   if (natMapping)
   {
      sr_nat_mapping_t *req, *prev = NULL, *next = NULL;
      for (req = nat->mappings; req != NULL; req = req->next)
      {
         if (req == natMapping)
         {
            if (prev)
            {
               next = req->next;
               prev->next = next;
            }
            else
            {
               next = req->next;
               nat->mappings = next;
            }
            
            break;
         }
         prev = req;
      }
      
      while (natMapping->conns != NULL)
      {
         sr_nat_connection_t * curr = natMapping->conns;
         natMapping->conns = curr->next;
         
         free(curr);
      }
      
      free(natMapping);
   }
}

static void sr_nat_destroy_connection(sr_nat_mapping_t* natMapping, sr_nat_connection_t* connection)
{
   sr_nat_connection_t *req, *prev = NULL, *next = NULL;
   
   if (natMapping && connection)
   {
      for (req = natMapping->conns; req != NULL; req = req->next)
      {
         if (req == connection)
         {
            if (prev)
            {
               next = req->next;
               prev->next = next;
            }
            else
            {
               next = req->next;
               natMapping->conns = next;
            }
            
            break;
         }
         prev = req;
      }
      
      if(connection->queuedInboundSyn)
      {
         free(connection->queuedInboundSyn);
      }
      
      free(connection);
   }
}

/**
 * NatHandleRecievedIpPacket()\n
 * @brief Called by router program when an IP packet is received and NAT functionality is enabled.
 * @param sr pointer to simple router struct.
 * @param ipPacket pointer to received packet.
 * @param length length of IP packet
 * @param receivedInterface pointer to the interface on which the packet was received.
 */
void NatHandleRecievedIpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
   sr_if_t const * const receivedInterface)
{
   if (ipPacket->ip_p == ip_protocol_tcp)
   {
      natHandleTcpPacket(sr, ipPacket, length, receivedInterface);
   }
   else if (ipPacket->ip_p == ip_protocol_icmp)
   {
      natHandleIcmpPacket(sr, ipPacket, length, receivedInterface);
   }
   else
   {
      LOG_MESSAGE("Received packet of unknown IP protocol type %u. Dropping.\n", ipPacket->ip_p);
   }
}

static void natHandleTcpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
   sr_if_t const * const receivedInterface)
{
   sr_tcp_hdr_t* tcpHeader = getTcpHeaderFromIpHeader(ipPacket);
   
   if (!TcpPerformIntegrityCheck(ipPacket, length))
   {
      LOG_MESSAGE("Received TCP packet with bad checksum. Dropping.\n");
      return;
   }
   
   if ((getInternalInterface(sr)->ip == receivedInterface->ip) && (IpDestinationIsUs(sr, ipPacket)))
   {
      IpHandleReceivedPacketToUs(sr, ipPacket, length, receivedInterface);
   }
   else if (getInternalInterface(sr)->ip == receivedInterface->ip)
   {
      sr_nat_mapping_t * natMapping = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src,
         tcpHeader->sourcePort, nat_mapping_tcp);
      
      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_M)
      {
         if (natMapping == NULL)
         {
            /* Outbound SYN with no prior mapping. Create one! */
            pthread_mutex_lock(&(sr->nat->lock));
            sr_nat_connection_t *firstConnection = malloc(sizeof(sr_nat_connection_t));
            sr_nat_mapping_t *sharedNatMapping;
            natMapping = malloc(sizeof(sr_nat_mapping_t));
            assert(firstConnection); assert(natMapping);
            
            sharedNatMapping = natTrustedCreateMapping(sr->nat, ipPacket->ip_src,
               tcpHeader->sourcePort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            /* Fill in first connection information. */
            firstConnection->connectionState = nat_conn_outbound_syn;
            firstConnection->lastAccessed = time(NULL);
            firstConnection->queuedInboundSyn = NULL;
            firstConnection->external.ipAddress = ipPacket->ip_dst;
            firstConnection->external.portNumber = tcpHeader->destinationPort;
            
            /* Add to the list of connections. */
            firstConnection->next = sharedNatMapping->conns;
            sharedNatMapping->conns = firstConnection;
            
            /* Create a copy so we can keep using it after we unlock the NAT table. */
            memcpy(natMapping, sharedNatMapping, sizeof(sr_nat_mapping_t));
            
            pthread_mutex_unlock(&(sr->nat->lock));
            
            LOG_MESSAGE("Added new TCP mapping %u.%u.%u.%u:%u <-> %u.\n", 
               (ntohl(natMapping->ip_int) >> 24) & 0xFF, (ntohl(natMapping->ip_int) >> 16) & 0xFF, 
               (ntohl(natMapping->ip_int) >> 8) & 0xFF, ntohl(natMapping->ip_int) & 0xFF, 
               ntohs(sharedNatMapping->aux_int), ntohs(sharedNatMapping->aux_ext));
         }
         else
         {
            /* Outbound SYN with prior mapping. Add the connection if one doesn't exist */
            pthread_mutex_lock(&(sr->nat->lock));
            sr_nat_mapping_t *sharedNatMapping = natTrustedLookupInternal(sr->nat, ipPacket->ip_src,
               tcpHeader->sourcePort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = natTrustedFindConnection(sharedNatMapping,
               ipPacket->ip_dst, tcpHeader->destinationPort);
            
            if (connection == NULL)
            {
               /* Connection does not exist. Create it. */
               connection = malloc(sizeof(sr_nat_connection_t));
               assert(connection);
               
               /* Fill in connection information. */
               connection->connectionState = nat_conn_outbound_syn;
               connection->external.ipAddress = ipPacket->ip_dst;
               connection->external.portNumber = tcpHeader->destinationPort;
               
               /* Add to the list of connections. */
               connection->next = sharedNatMapping->conns;
               sharedNatMapping->conns = connection;
               
               LOG_MESSAGE("Added new connection to TCP mapping %u.%u.%u.%u:%u <-> %u.\n", 
                  (ntohl(natMapping->ip_int) >> 24) & 0xFF, (ntohl(natMapping->ip_int) >> 16) & 0xFF, 
                  (ntohl(natMapping->ip_int) >> 8) & 0xFF, ntohl(natMapping->ip_int) & 0xFF, 
                  ntohs(natMapping->aux_int), ntohs(natMapping->aux_ext));
            }
            else if (connection->connectionState == nat_conn_time_wait)
            {
               /* Give client opportunity to reopen the connection. */
               connection->connectionState = nat_conn_outbound_syn;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
               connection->connectionState = nat_conn_connected;
               
               /* As per lab instructions, silently drop the original 
                * unsolicited inbound SYN */
               if (connection->queuedInboundSyn) { free(connection->queuedInboundSyn); }
            }
            /* Only other options are connected and outbound syn, in which we 
             * assume this is a retried packet. */
            
            pthread_mutex_unlock(&(sr->nat->lock));
         }
      }
      else if (natMapping == NULL)
      {
         /* TCP packet attempted to traverse the NAT on an unopened 
          * connection. What to do? Silently drop the packet. */
         LOG_MESSAGE("Outbound non-SYN TCP packet attempted to traverse NAT "
            "when no mapping existed. Dropping.\n");
         return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_M)
      {
         /* Outbound FIN detected. Put connection into TIME_WAIT state. */
         pthread_mutex_lock(&(sr->nat->lock));
         sr_nat_mapping_t *sharedNatMapping = natTrustedLookupInternal(sr->nat, ipPacket->ip_src,
            tcpHeader->sourcePort, nat_mapping_tcp);
         sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, 
            ipPacket->ip_dst, tcpHeader->destinationPort);
         
         if (associatedConnection)
         {
            associatedConnection->connectionState = nat_conn_time_wait;
         }
         
         pthread_mutex_unlock(&(sr->nat->lock));
      }
      
      /* All NAT state updating done by this point. Translate and forward. */
      natHandleReceivedOutboundIpPacket(sr, ipPacket, length, receivedInterface, natMapping);
      
      if (natMapping) { free(natMapping); }
   }
   else /* Inbound TCP packet */
   {
      sr_nat_mapping_t * natMapping = sr_nat_lookup_external(sr->nat, tcpHeader->destinationPort,
         nat_mapping_tcp);
      
      if (ntohs(tcpHeader->offset_controlBits) & TCP_SYN_M)
      {
         /* Inbound SYN received. */
         if (natMapping == NULL)
         {
            /* In the case that there is no mapping, no hole can be blown 
             * through the NAT for simultaneous open. Thus we immediately call 
             * the port as closed. */
            IpSendTypeThreeIcmpPacket(sr, icmp_code_destination_port_unreachable, ipPacket);
            return;
         }
         else
         {
            /* Potential simultaneous open */
            pthread_mutex_lock(&(sr->nat->lock));
            
            sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, 
               tcpHeader->destinationPort, nat_mapping_tcp);
            assert(sharedNatMapping);
            
            sr_nat_connection_t *connection = natTrustedFindConnection(sharedNatMapping,
               ipPacket->ip_src, tcpHeader->sourcePort);
            
            if (connection == NULL)
            {
               /* Potential simultaneous open. */
               connection = malloc(sizeof(sr_nat_connection_t));
               assert(connection);
               
               /* Fill in connection information. */
               connection->connectionState = nat_conn_inbound_syn_pending;
               connection->queuedInboundSyn = malloc(length);
               memcpy(connection->queuedInboundSyn, ipPacket, length);
               connection->external.ipAddress = ipPacket->ip_src;
               connection->external.portNumber = tcpHeader->sourcePort;
               
               /* Add to the list of connections. */
               connection->next = sharedNatMapping->conns;
               sharedNatMapping->conns = connection;
               
               LOG_MESSAGE("Added new connection to TCP mapping %u.%u.%u.%u:%u <-> %u.\n", 
                  (ntohl(natMapping->ip_int) >> 24) & 0xFF, (ntohl(natMapping->ip_int) >> 16) & 0xFF, 
                  (ntohl(natMapping->ip_int) >> 8) & 0xFF, ntohl(natMapping->ip_int) & 0xFF, 
                  ntohs(natMapping->aux_int), ntohs(natMapping->aux_ext));
               return;
            }
            else if (connection->connectionState == nat_conn_inbound_syn_pending)
            {
               /* Retry of inbound SYN. Silently drop. */
               return;
            }
            else if (connection->connectionState == nat_conn_outbound_syn)
            {
               /* Connection UP! */
               connection->connectionState = nat_conn_connected;
            }
            
            pthread_mutex_unlock(&(sr->nat->lock));
         }
      }
      else if (natMapping == NULL)
      {
         /* TCP packet attempted to traverse the NAT on an unopened 
          * connection. What to do? LOUDLY drop the packet. */
         LOG_MESSAGE("Inbound non-SYN TCP packet attempted to traverse NAT "
            "when no mapping existed. Dropping.\n");
         IpSendTypeThreeIcmpPacket(sr, icmp_code_destination_port_unreachable, ipPacket);
         return;
      }
      else if (ntohs(tcpHeader->offset_controlBits) & TCP_FIN_M)
      {
         /* Inbound FIN detected. Put connection into TIME_WAIT state. */
         pthread_mutex_lock(&(sr->nat->lock));
         sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, 
            tcpHeader->destinationPort, nat_mapping_tcp);
         sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, 
            ipPacket->ip_src, tcpHeader->sourcePort);
         
         if (associatedConnection)
         {
            associatedConnection->connectionState = nat_conn_time_wait;
         }
         
         pthread_mutex_unlock(&(sr->nat->lock));
      }
      else
      {
         /* Lookup the associated connection to "touch" it and keep it alive. */
         pthread_mutex_lock(&(sr->nat->lock));
         sr_nat_mapping_t *sharedNatMapping = natTrustedLookupExternal(sr->nat, 
            tcpHeader->destinationPort, nat_mapping_tcp);
         sr_nat_connection_t *associatedConnection = natTrustedFindConnection(sharedNatMapping, 
            ipPacket->ip_src, tcpHeader->sourcePort);
         
         if (associatedConnection == NULL)
         {
            /* Received unsolicited non-SYN packet when no active connection was found. */
            pthread_mutex_unlock(&(sr->nat->lock));
            
            LOG_MESSAGE("Received non-SYN inbound TCP packet, but no active associated connection. Dropping.\n");
            return;
         }
         else
         {
            pthread_mutex_unlock(&(sr->nat->lock));
         }
      }
      
      /* If the packet made it here, it's okay to traverse. */
      natHandleReceivedInboundIpPacket(sr, ipPacket, length, receivedInterface, natMapping);
      
      if (natMapping) { free(natMapping); }
   }
}

static void natHandleIcmpPacket(sr_instance_t* sr, sr_ip_hdr_t* ipPacket, unsigned int length,
   sr_if_t const * const receivedInterface)
{
   sr_icmp_hdr_t * icmpHeader = getIcmpHeaderFromIpHeader(ipPacket);
   
   if (!IcmpPerformIntegrityCheck(icmpHeader, length - getIpHeaderLength(ipPacket)))
   {
      LOG_MESSAGE("Received ICMP packet with bad checksum. Dropping.\n");
      return;
   }
   
   if ((getInternalInterface(sr)->ip == receivedInterface->ip) && (IpDestinationIsUs(sr, ipPacket)))
   {
      IpHandleReceivedPacketToUs(sr, ipPacket, length, receivedInterface);
   }
   else if (getInternalInterface(sr)->ip == receivedInterface->ip)
   {
      if ((icmpHeader->icmp_type == icmp_type_echo_request)
         || (icmpHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t * icmpPingHdr = (sr_icmp_t0_hdr_t *) icmpHeader;
         sr_nat_mapping_t * natLookupResult = sr_nat_lookup_internal(sr->nat, ipPacket->ip_src, 
            icmpPingHdr->ident, nat_mapping_icmp);
         
         /* No mapping? Make one! */
         if (natLookupResult == NULL)
         {
            natLookupResult = sr_nat_insert_mapping(sr->nat, ipPacket->ip_src, icmpPingHdr->ident,
               nat_mapping_icmp);
         }
         
         natHandleReceivedOutboundIpPacket(sr, ipPacket, length, receivedInterface, natLookupResult);
         free(natLookupResult);
      }
      else if (icmpHeader->icmp_type == icmp_type_desination_unreachable)
      {
         
      }
      else if (icmpHeader->icmp_type == icmp_type_time_exceeded)
      {
         
      }
      else
      {
         /* By RFC, no other ICMP types have to support NAT traversal (SHOULDs 
          * instead of MUSTs). It's not that I'm lazy, it's just that this 
          * assignment is hard enough as it is. */
         LOG_MESSAGE("Dropping unsupported outbound ICMP packet Type: %u Code: %u.\n", 
            icmpHeader->icmp_type, icmpHeader->icmp_code);
      }
   }
   else /* Inbound ICMP packet */
   {
      if (!IpDestinationIsUs(sr, ipPacket))
      {
         if (getInternalInterface(sr)->ip
            != sr_get_interface(sr, IpGetPacketRoute(sr, ntohl(ipPacket->ip_dst))->interface)->ip)
         {
            /* Sender not attempting to traverse the NAT. Allow the packet to 
             * be routed without alteration. */
            IpForwardIpPacket(sr, ipPacket, length, receivedInterface);
         }
         else
         {
            LOG_MESSAGE("Unsolicited inbound ICMP packet received attempting to send to internal IP. Dropping.\n");
         }
         return;
      }
      else if (ipPacket->ip_dst == getInternalInterface(sr)->ip)
      {
         /* Disallow sending packet to our internal interface. */
         LOG_MESSAGE("Received ICMP packet to our internal interface. Dropping.\n");
         //TODO: Type 3 ICMP response?
         return;
      }
      else if ((icmpHeader->icmp_type == icmp_type_echo_request)
         || (icmpHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t * icmpPingHdr = (sr_icmp_t0_hdr_t *) icmpHeader;
         sr_nat_mapping_t * natLookupResult = sr_nat_lookup_external(sr->nat, icmpPingHdr->ident, 
            nat_mapping_icmp);
         
         if (natLookupResult == NULL)
         {
            /* No mapping exists. Assume ping is actually for us. */
            IpHandleReceivedPacketToUs(sr, ipPacket, length, receivedInterface);
         }
         else
         {
            natHandleReceivedInboundIpPacket(sr, ipPacket, length, receivedInterface,
               natLookupResult);
            free (natLookupResult);
         }
      }
      else if (icmpHeader->icmp_type == icmp_type_desination_unreachable)
      {
         
      }
      else if (icmpHeader->icmp_type == icmp_type_time_exceeded)
      {
         
      }
      else
      {
         /* By RFC, no other ICMP types have to support NAT traversal (SHOULDs 
          * instead of MUSTs). It's not that I'm lazy, it's just that this 
          * assignment is hard enough as it is. */
         LOG_MESSAGE("Dropping unsupported inbound ICMP packet Type: %u Code: %u.\n", 
            icmpHeader->icmp_type, icmpHeader->icmp_code);
      }
   }
}

/**
 * NatUndoPacketMapping()\n
 * @brief Called by the router code when an IP datagram needs its NAT translation undone (like when TTL is exceeded).
 * @param sr pointer to simple router struct.
 * @param mutatedPacket pointer to previously mutated IP datagram
 * @param length length of IP datagram.
 * @param receivedInterface pointer on which the mutated packet was originally received.
 */
void NatUndoPacketMapping(sr_instance_t* sr, sr_ip_hdr_t* mutatedPacket, unsigned int length, 
   sr_if_t const * const receivedInterface)
{
   sr_nat_mapping_t * natMap;
   if (getInternalInterface(sr)->ip == receivedInterface->ip)
   {
      /* Undo an outbound conversion. */
      if (mutatedPacket->ip_p == ip_protocol_icmp)
      {
         sr_icmp_t0_hdr_t * icmpHeader = (sr_icmp_t0_hdr_t *) getIcmpHeaderFromIpHeader(
            mutatedPacket);
         natMap = sr_nat_lookup_external(sr->nat, icmpHeader->ident, nat_mapping_icmp);
         if (natMap != NULL)
         {
            icmpHeader->ident = natMap->aux_int;
            icmpHeader->icmp_sum = 0;
            icmpHeader->icmp_sum = cksum(icmpHeader, length - getIpHeaderLength(mutatedPacket));
            
            mutatedPacket->ip_src = natMap->ip_int;
            mutatedPacket->ip_sum = 0;
            mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
         }
         free(natMap);
      }
      else if (mutatedPacket->ip_p == ip_protocol_tcp)
      {
         sr_tcp_hdr_t * tcpHeader = getTcpHeaderFromIpHeader(mutatedPacket);
         natMap = sr_nat_lookup_external(sr->nat, tcpHeader->sourcePort, nat_mapping_tcp);
         if (natMap != NULL)
         {
            tcpHeader->sourcePort = natMap->aux_int;
            mutatedPacket->ip_src = natMap->ip_int;
            
            natRecalculateTcpChecksum(mutatedPacket, length);
            
            mutatedPacket->ip_sum = 0;
            mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
         }
         free(natMap);
      }
   }
   else
   {
      /* Undo an potential inbound conversion. If the lookup fails, we can 
       * assume this packet did not cross through the NAT. */
      if (mutatedPacket->ip_p == ip_protocol_icmp)
      {
         sr_icmp_t0_hdr_t * icmpHeader = (sr_icmp_t0_hdr_t *) (((uint8_t *) mutatedPacket)
            + getIpHeaderLength(mutatedPacket));
         natMap = sr_nat_lookup_internal(sr->nat, ntohl(mutatedPacket->ip_dst), 
            ntohs(icmpHeader->ident), nat_mapping_icmp);
         if (natMap != NULL)
         {
            icmpHeader->ident = htons(natMap->aux_ext);
            icmpHeader->icmp_sum = 0;
            icmpHeader->icmp_sum = cksum(icmpHeader, length - getIpHeaderLength(mutatedPacket));
            
            mutatedPacket->ip_dst = sr_get_interface(sr,
               IpGetPacketRoute(sr, mutatedPacket->ip_src)->interface)->ip;
            mutatedPacket->ip_sum = 0;
            mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
            
            free(natMap);
         }
      }
      else if (mutatedPacket->ip_p == ip_protocol_tcp)
      {
         sr_tcp_hdr_t * tcpHeader = (sr_tcp_hdr_t *) (((uint8_t *) mutatedPacket)
            + getIpHeaderLength(mutatedPacket));
         natMap = sr_nat_lookup_internal(sr->nat, ntohl(mutatedPacket->ip_dst), 
            ntohs(tcpHeader->destinationPort), nat_mapping_icmp);
         if (natMap != NULL)
         {
            tcpHeader->destinationPort = htons(natMap->aux_ext);
            mutatedPacket->ip_dst = sr_get_interface(sr,
               IpGetPacketRoute(sr, mutatedPacket->ip_src)->interface)->ip;
            
            natRecalculateTcpChecksum(mutatedPacket, length);
            
            mutatedPacket->ip_sum = 0;
            mutatedPacket->ip_sum = cksum(mutatedPacket, getIpHeaderLength(mutatedPacket));
            
            free(natMap);
         }
      }
   }
}

static void natHandleReceivedOutboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet,
   unsigned int length, const struct sr_if* const receivedInterface, sr_nat_mapping_t * natMapping)
{
   if (packet->ip_p == ip_protocol_icmp)
   {
      sr_icmp_hdr_t *icmpPacketHeader = (sr_icmp_hdr_t *) (((uint8_t*) packet)
         + getIpHeaderLength(packet));

      if ((icmpPacketHeader->icmp_type == icmp_type_echo_request)
         || (icmpPacketHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t* rewrittenIcmpHeader = (sr_icmp_t0_hdr_t*) icmpPacketHeader;
         int icmpLength = length - getIpHeaderLength(packet);
         
         assert(natMapping);
         
         /* Handle ICMP identify remap and validate. */
         rewrittenIcmpHeader->ident = natMapping->aux_ext;
         rewrittenIcmpHeader->icmp_sum = 0;
         rewrittenIcmpHeader->icmp_sum = cksum(rewrittenIcmpHeader, icmpLength);
         
         /* Handle IP address remap and validate. */
         packet->ip_src = sr_get_interface(sr,
            IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
      else if (icmpPacketHeader->icmp_type == icmp_type_desination_unreachable)
      {
         /* This packet is actually associated with a stream. */
         assert(packet->ip_p == ip_protocol_tcp);
      }
   }
   else if (packet->ip_p == ip_protocol_tcp)
   {
      sr_tcp_hdr_t* tcpHeader = (sr_tcp_hdr_t *) (((uint8_t*) packet) + getIpHeaderLength(packet));
      
      tcpHeader->sourcePort = natMapping->aux_ext;
      packet->ip_src = sr_get_interface(sr,
         IpGetPacketRoute(sr, ntohl(packet->ip_dst))->interface)->ip;
      
      natRecalculateTcpChecksum(packet, length);
      IpForwardIpPacket(sr, packet, length, receivedInterface);
   }
   /* If another protocol, should have been dropped by now. */
}

static void natHandleReceivedInboundIpPacket(struct sr_instance* sr, sr_ip_hdr_t* packet, 
   unsigned int length, const struct sr_if* const receivedInterface, sr_nat_mapping_t * natMapping)
{
   if (packet->ip_p == ip_protocol_icmp)
   {
      sr_icmp_hdr_t *icmpPacketHeader = getIcmpHeaderFromIpHeader(packet);
      
      if ((icmpPacketHeader->icmp_type == icmp_type_echo_request)
         || (icmpPacketHeader->icmp_type == icmp_type_echo_reply))
      {
         sr_icmp_t0_hdr_t *echoPacketHeader = (sr_icmp_t0_hdr_t *) icmpPacketHeader;
         int icmpLength = length - getIpHeaderLength(packet);
         
         assert(natMapping);
         
         /* Handle ICMP identify remap and validate. */
         echoPacketHeader->ident = natMapping->aux_int;
         echoPacketHeader->icmp_sum = 0;
         echoPacketHeader->icmp_sum = cksum(echoPacketHeader, icmpLength);
         
         /* Handle IP address remap and validate. */
         packet->ip_dst = natMapping->ip_int;
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
      else if (icmpPacketHeader->icmp_type == icmp_type_desination_unreachable)
      {
         /* This packet is actually associated with a stream. */
         sr_icmp_t3_hdr_t *unreachablePacketHeader = (sr_icmp_t3_hdr_t *) icmpPacketHeader;
         int icmpLength = length - getIpHeaderLength(packet);
         sr_ip_hdr_t *originalDatagram = (sr_ip_hdr_t*) (unreachablePacketHeader->data);
         sr_tcp_hdr_t *originalTransportHeader = getTcpHeaderFromIpHeader(originalDatagram);
         
         assert(natMapping);
         assert(originalDatagram->ip_p == ip_protocol_tcp);
         
         /* Perform mapping on embedded payload */
         originalTransportHeader->sourcePort = natMapping->ip_int;
         originalDatagram->ip_src = natMapping->ip_int;
         
         /* Update ICMP checksum */
         unreachablePacketHeader->icmp_sum = 0;
         unreachablePacketHeader->icmp_sum = cksum(unreachablePacketHeader, icmpLength);
         
         /* Rewrite actual packet header. */
         packet->ip_dst = natMapping->ip_int;
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
      else if (icmpPacketHeader->icmp_type == icmp_type_time_exceeded)
      {
         /* This packet is actually associated with a stream. */
         sr_icmp_t11_hdr_t *exceededPacketHeader = (sr_icmp_t11_hdr_t *) icmpPacketHeader;
         int icmpLength = length - getIpHeaderLength(packet);
         sr_ip_hdr_t *originalDatagram = (sr_ip_hdr_t*) (exceededPacketHeader->data);
         
         assert(natMapping);
         
         if (natMapping->type == nat_mapping_tcp)
         {
            sr_tcp_hdr_t *originalTransportHeader = (sr_tcp_hdr_t*) (((uint8_t*) icmpPacketHeader)
               + getIpHeaderLength(packet));
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->sourcePort = natMapping->ip_int;
            originalDatagram->ip_src = natMapping->ip_int;
            
            /* Update ICMP checksum */
            exceededPacketHeader->icmp_sum = 0;
            exceededPacketHeader->icmp_sum = cksum(exceededPacketHeader, icmpLength);
            
            /* Rewrite actual packet header. */
            packet->ip_dst = natMapping->ip_int;
         }
         else if (natMapping->type == nat_mapping_icmp)
         {
            /* T0 & T8 are the only types of ICMP messages that can generate 
             * an TTL Exceeded packet in response. */
            sr_icmp_t0_hdr_t *originalTransportHeader =
               (sr_icmp_t0_hdr_t *) (((uint8_t*) icmpPacketHeader) + getIpHeaderLength(packet));
            
            /* Perform mapping on embedded payload */
            originalTransportHeader->ident = natMapping->aux_int;
            
            /* Handle IP address remap */
            packet->ip_dst = natMapping->ip_int;
         }
         else
         {
            return;
         }
         
         IpForwardIpPacket(sr, packet, length, receivedInterface);
      }
   }
   else if (packet->ip_p == ip_protocol_tcp)
   {
      sr_tcp_hdr_t* tcpHeader = (sr_tcp_hdr_t *) (((uint8_t*) packet) + getIpHeaderLength(packet));
            
      tcpHeader->destinationPort = natMapping->aux_int;
      packet->ip_dst = natMapping->ip_int;
      
      natRecalculateTcpChecksum(packet, length);
      IpForwardIpPacket(sr, packet, length, receivedInterface);
   }
}

/**
 * natPacketDestination()\n
 * @brief Checks NAT lookup table to find the destination of a received packet.
 * @param sr pointer to the simple router state structure.
 * @param packet pointer to the received IP datagram.
 * @param length length of the received IP datagram.
 * @param receivedInterface pointer to the interface structure on which the packet was received.
 * @param associatedMapping an output value of the associated NAT mapping if one exists. Valid 
 *        when INBOUND or OUTBOUND are returned. Memory needs to be allocated by the calling 
 *        function for this to be populated.
 * @return NAT_PACKET_FOR_ROUTER if the packet is for us.
 * @return NAT_PACKET_DROP if the packet should be dropped (bad checksum, unsupported protocol, etc.)
 * @return NAT_PACKET_OUTBOUND if the packet is traversing the NAT from internal -> external.
 * @return NAT_PACKET_INBOUND if the packet is traversing the NAT from external -> internal.
 * @return NAT_PACKET_DEFLECTION if the packet is not traversing the NAT (external -> external).
 */
static NatDestinationResult_t natPacketDestination(sr_instance_t * sr, 
   sr_ip_hdr_t * const packet, unsigned int length, sr_if_t const * const receivedInterface,
   sr_nat_mapping_t * associatedMapping)
{
   sr_nat_mapping_t * natLookupResult = NULL;
   if (getInternalInterface(sr)->ip == receivedInterface->ip)
   {
      if (IpDestinationIsUs(sr, packet))
      {
         return NAT_PACKET_FOR_ROUTER;
      }
      
      if (packet->ip_p == ip_protocol_tcp)
      {
         sr_tcp_hdr_t * const tcpHdr = (sr_tcp_hdr_t * const ) (((uint8_t*) packet)
            + getIpHeaderLength(packet));
         
         if (!TcpPerformIntegrityCheck(packet, length))
         {
            LOG_MESSAGE("ICMP checksum of received packet failed. Dropping.\n");
            return NAT_PACKET_DROP;
         }
         
         natLookupResult = sr_nat_lookup_internal(sr->nat, ntohl(packet->ip_src),
            ntohs(tcpHdr->sourcePort), nat_mapping_tcp);
         
         if ((natLookupResult == NULL) && (ntohs(tcpHdr->offset_controlBits) & TCP_SYN_M))
         {
            /* The packet is an outbound SYN. Make a mapping. */
            natLookupResult = sr_nat_insert_mapping(sr->nat, ntohl(packet->ip_src),
               ntohs(tcpHdr->sourcePort), nat_mapping_tcp);
         }
         else if ((natLookupResult->conns->connectionState != nat_conn_connected) 
            && (ntohs(tcpHdr->offset_controlBits) & TCP_SYN_M))
         {
            if (natLookupResult->conns->connectionState == nat_conn_inbound_syn_pending)
            {
               /* Simulataneous open successful */
            }
            else if (natLookupResult->conns->connectionState == nat_conn_time_wait)
            {
               natLookupResult->conns->connectionState = nat_conn_outbound_syn;
            }
         }

         if (associatedMapping != NULL )
         {
            memcpy(associatedMapping, natLookupResult, sizeof(sr_nat_mapping_t));
         }
         free(natLookupResult);
         
         return NAT_PACKET_OUTBOUND;
      }
      else if (packet->ip_p == ip_protocol_icmp)
      {
         sr_icmp_hdr_t * const icmpHdr =
            (sr_icmp_hdr_t * const ) (((uint8_t*) packet) + getIpHeaderLength(packet));
         
         if (!IcmpPerformIntegrityCheck(icmpHdr, length - getIpHeaderLength(packet)))
         {
            LOG_MESSAGE("ICMP checksum of received packet failed. Dropping.\n");
            return NAT_PACKET_DROP;
         }
         
         if (icmpHdr->icmp_type == icmp_type_desination_unreachable)
         {
            /* Rather than attempting to find an associated ICMP mapping, we need to 
             * find an associated TCP mapping. */
            sr_icmp_t3_hdr_t * const icmpUnreachHdr =
               (sr_icmp_t3_hdr_t * const ) icmpHdr;
            
            /* The data section of an ICMP destination unreachable should be 
             * the associated packet's IP header and first 8 bytes of the IP 
             * payload. */
            sr_ip_hdr_t * const errorPacket =
               (sr_ip_hdr_t * const ) icmpUnreachHdr->data;
            
            if (errorPacket->ip_p == ip_protocol_tcp)
            {
               sr_tcp_hdr_t * const errorTcpHdr = (sr_tcp_hdr_t * const ) (((uint8_t*) errorPacket)
                  + getIpHeaderLength(errorPacket));
               natLookupResult = sr_nat_lookup_external(sr->nat, ntohs(errorTcpHdr->sourcePort),
                  nat_mapping_tcp);
               if (natLookupResult != NULL)
               {
                  /* Hmm...seems like an okay mapping. */
                  if (associatedMapping != NULL)
                  {
                     memcpy(associatedMapping, natLookupResult, sizeof(sr_nat_mapping_t));
                  }
                  free(natLookupResult);
                  
                  return NAT_PACKET_INBOUND;
               }
               else
               {
                  /* No associated mapping. Drop it like it's hot! */
                  return NAT_PACKET_DROP;
               }
            }
            else if (errorPacket->ip_p == ip_protocol_icmp)
            {
               sr_icmp_t0_hdr_t * const errorIcmpHdr = (sr_icmp_t0_hdr_t * const ) (((uint8_t*) errorPacket)
                  + getIpHeaderLength(errorPacket));
               natLookupResult = sr_nat_lookup_external(sr->nat, ntohs(errorIcmpHdr->ident),
                  nat_mapping_icmp);
               if (natLookupResult != NULL)
               {
                  /* Hmm...seems like an okay mapping. */
                  if (associatedMapping != NULL)
                  {
                     memcpy(associatedMapping, natLookupResult, sizeof(sr_nat_mapping_t));
                  }
                  free(natLookupResult);
                  
                  return NAT_PACKET_INBOUND;
               }
               else
               {
                  /* No associated mapping. Drop it like it's hot! */
                  return NAT_PACKET_DROP;
               }
            }
            else
            {
               /* Unsupported protocol. No way we have a mapping. */
               return NAT_PACKET_DROP;
            }
         }
         else if ((icmpHdr->icmp_type == icmp_type_echo_reply)
            || (icmpHdr->icmp_type == icmp_type_echo_request))
         {
            sr_icmp_t0_hdr_t * const icmpPingHdr =
               (sr_icmp_t0_hdr_t * const ) icmpHdr;
            
            natLookupResult = sr_nat_lookup_internal(sr->nat, ntohl(packet->ip_src), ntohs(icmpPingHdr->ident),
               nat_mapping_icmp);
            if (natLookupResult == NULL)
            {
               natLookupResult = sr_nat_insert_mapping(sr->nat, ntohl(packet->ip_src), ntohs(icmpPingHdr->ident),
                  nat_mapping_icmp);
            }
            
            if (associatedMapping != NULL)
            {
               memcpy(associatedMapping, natLookupResult, sizeof(sr_nat_mapping_t));
            }
            
            free(natLookupResult);
            
            return NAT_PACKET_OUTBOUND;
         }
         else
         {
            /* Non-required ICMP message type. To hell with best effort. */
            return NAT_PACKET_DROP;
         }
      }
      else
      {
         /* Unknown protocol type. */
         return NAT_PACKET_DROP;
      }
   }
   else
   {
      if (!IpDestinationIsUs(sr, packet))
      {
         /* If an external host wants to traverse the NAT, it would have sent 
          * the packet to us! Assume we are supposed to act like a router and 
          * forward to another external interface. */
         return NAT_PACKET_DEFLECTION;
      }
      
      if (packet->ip_p == ip_protocol_icmp)
      {
         sr_icmp_hdr_t * const icmpHdr = (sr_icmp_hdr_t * const ) (((uint8_t*) packet)
            + getIpHeaderLength(packet));
         
         if (!IcmpPerformIntegrityCheck(icmpHdr, length - getIpHeaderLength(packet)))
         {
            LOG_MESSAGE("ICMP checksum of received packet failed. Dropping.\n");
            return NAT_PACKET_DROP;
         }
         
         if (icmpHdr->icmp_type == icmp_type_desination_unreachable)
         {
            /* Attempt to fulfill RFC-5382 REQ-9. Check for an associated TCP 
             * connection for this ICMP error packet. */
            sr_icmp_t3_hdr_t * const icmpUnreachHdr =
               (sr_icmp_t3_hdr_t * const ) icmpHdr;
            
            /* The data section of an ICMP destination unreachable should be 
             * the associated packet's IP header and first 8 bytes of the IP 
             * payload. */
            sr_ip_hdr_t * const errorPacket =
               (sr_ip_hdr_t * const ) icmpUnreachHdr->data;
            sr_tcp_hdr_t * const errorTcpHdr =
               (sr_tcp_hdr_t * const ) (((uint8_t*) errorPacket)
                  + getIpHeaderLength(errorPacket));
            
            if (errorPacket->ip_p == ip_protocol_tcp)
            {
               natLookupResult = sr_nat_lookup_external(sr->nat, ntohs(errorTcpHdr->sourcePort),
                  nat_mapping_tcp);
               if (natLookupResult != NULL)
               {
                  /* Hmm...seems legit. */
                  if (associatedMapping != NULL)
                  {
                     memcpy(associatedMapping, natLookupResult, sizeof(sr_nat_mapping_t));
                  }
                  
                  free(natLookupResult);
                  return NAT_PACKET_INBOUND;
               }
               else
               {
                  /* No associated mapping. Drop it like it's hot! */
                  return NAT_PACKET_DROP;
               }
            }
            else
            {
               /* Unsupported protocol. No way we have a mapping. */
               return NAT_PACKET_DROP;
            }
         }
         else if ((icmpHdr->icmp_type == icmp_type_echo_reply) 
            || (icmpHdr->icmp_type == icmp_type_echo_request))
         {
            sr_icmp_t0_hdr_t * const icmpPingHdr =
               (sr_icmp_t0_hdr_t * const ) icmpHdr;
            natLookupResult = sr_nat_lookup_external(sr->nat, ntohs(icmpPingHdr->ident),
               nat_mapping_icmp);
            if (natLookupResult != NULL)
            {
               if (associatedMapping != NULL)
               {
                  memcpy(associatedMapping, natLookupResult, sizeof(sr_nat_mapping_t));
               }
               
               free(natLookupResult);
               return NAT_PACKET_INBOUND;
            }
            else
            {
               /* Assume it is for us. ICMP handling code will reject it if 
                * necessary. */
               return NAT_PACKET_FOR_ROUTER;
            }
         }
         else
         {
            /* To hell with best effort. */
            return NAT_PACKET_DROP;
         }
      }
      else if (packet->ip_p == ip_protocol_tcp)
      {
         /* So much easier than ICMP. Lookup and see what the story is. */
         sr_tcp_hdr_t * const tcpHdr = (sr_tcp_hdr_t * const ) (((uint8_t*) packet)
            + getIpHeaderLength(packet));
         
         if (!TcpPerformIntegrityCheck(packet, length))
         {
            LOG_MESSAGE("TCP checksum of inbound packet failed. Dropping packet.\n");
            return NAT_PACKET_DROP;
         }
         
         pthread_mutex_lock(&(sr->nat->lock));
         natLookupResult = natTrustedLookupExternal(sr->nat, ntohs(tcpHdr->destinationPort),
            nat_mapping_tcp);
         if (natLookupResult != NULL)
         {
            if ((natLookupResult->conns->connectionState != nat_conn_connected) 
               && (ntohs(tcpHdr->offset_controlBits) & TCP_SYN_M))
            {
               if (natLookupResult->conns->connectionState == nat_conn_outbound_syn)
               {
                  LOG_MESSAGE("Mapping from %u.%u.%u.%u:%u to %u now connected.\n", 
                     (natLookupResult->ip_int >> 24) & 0xFF, (natLookupResult->ip_int >> 16) & 0xFF, 
                     (natLookupResult->ip_int >> 8) & 0xFF, natLookupResult->ip_int & 0xFF, 
                     natLookupResult->aux_int, natLookupResult->aux_ext);
                  natLookupResult->conns->connectionState = nat_conn_connected;
               }
            }
            natLookupResult->last_updated = time(NULL);
            
            if (associatedMapping != NULL)
            {
               memcpy(associatedMapping, natLookupResult, sizeof(sr_nat_mapping_t));
            }
            
            pthread_mutex_unlock(&(sr->nat->lock));
            return NAT_PACKET_INBOUND;
         }
         else if (ntohs(tcpHdr->offset_controlBits) & TCP_SYN_M)
         {
            /* Assume external client is attempting a simultaneous open. */
            natLookupResult = natTrustedCreateMapping(sr->nat, 0, ntohs(tcpHdr->destinationPort), nat_mapping_tcp);
            natLookupResult->ip_ext = ntohl(packet->ip_src);
            return NAT_PACKET_INBOUND;
         }
         else
         {
            /* Assume it is for us. TCP handling code will reject it with a 
             * port unreachable. */
            pthread_mutex_unlock(&(sr->nat->lock));
            return NAT_PACKET_FOR_ROUTER;
         }
      }
      else
      {
         /* Apparently my best effort is just not good enough. Unsupported 
          * protocol. */
         return NAT_PACKET_DROP;
      }
   }
}

static void natRecalculateTcpChecksum(sr_ip_hdr_t * tcpPacket, unsigned int length)
{
   unsigned int tcpLength = length - getIpHeaderLength(tcpPacket);
   uint8_t *packetCopy = malloc(sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   sr_tcp_ip_pseudo_hdr_t * checksummedHeader = (sr_tcp_ip_pseudo_hdr_t *) packetCopy;
   sr_tcp_hdr_t * const tcpHeader = (sr_tcp_hdr_t * const ) (((uint8_t*) tcpPacket)
      + getIpHeaderLength(tcpPacket));
   
   /* I wish there was a better way to do this with pointer magic, but I don't 
    * see it. Make a copy of the packet and prepend the IP pseudo-header to 
    * the front. */
   memcpy(packetCopy + sizeof(sr_tcp_ip_pseudo_hdr_t), tcpHeader, tcpLength);
   checksummedHeader->sourceAddress = tcpPacket->ip_src;
   checksummedHeader->destinationAddress = tcpPacket->ip_dst;
   checksummedHeader->zeros = 0;
   checksummedHeader->protocol = ip_protocol_tcp;
   checksummedHeader->tcpLength = htons(tcpLength);
   
   tcpHeader->checksum = 0;
   tcpHeader->checksum = cksum(packetCopy, sizeof(sr_tcp_ip_pseudo_hdr_t) + tcpLength);
   
   free(packetCopy);
}

static sr_nat_connection_t * natTrustedFindConnection(sr_nat_mapping_t *natEntry, uint32_t ip_ext, 
   uint16_t port_ext)
{
   sr_nat_connection_t * connectionIterator = natEntry->conns;
   while (connectionIterator != NULL)
   {
      if ((connectionIterator->external.ipAddress == ip_ext) 
         && (connectionIterator->external.portNumber == port_ext))
      {
         connectionIterator->lastAccessed = time(NULL);
         break;
      }
      
      connectionIterator = connectionIterator->next;
   }
   return connectionIterator;
}
