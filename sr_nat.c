#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef DONT_DEFINE_UNLESS_DEBUGGING
# define LOG_MESSAGE(...) fprintf(stderr, __VA_ARGS__)
#else 
# define LOG_MESSAGE(...)
#endif

static void sr_nat_destroy_mapping(sr_nat_t* nat, sr_nat_mapping_t* natMapping);

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
                  LOG_MESSAGE("ICMP mapping from %u.%u.%u.%u:%u to %u timed out.\n", 
                     (mappingWalker->ip_int >> 24) & 0xFF, (mappingWalker->ip_int >> 16) & 0xFF, 
                     (mappingWalker->ip_int >> 8) & 0xFF, mappingWalker->ip_int & 0xFF, 
                     mappingWalker->aux_int, mappingWalker->aux_ext);
                  sr_nat_destroy_mapping(nat, mappingWalker);
                  mappingWalker = next;
               }
               else
               {
                  mappingWalker = mappingWalker->next;
               }
               break;
               
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
   sr_nat_mapping_t *mappingWalker;
   
   for (mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
   {
      if ((mappingWalker->type == type) && (mappingWalker->aux_ext == aux_ext))
      {
         mappingWalker->last_updated = time(NULL);
         copy = malloc(sizeof(sr_nat_mapping_t));
         memcpy(copy, mappingWalker, sizeof(sr_nat_mapping_t));
         break;
      }
   }
   
   pthread_mutex_unlock(&(nat->lock));
   return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   pthread_mutex_lock(&(nat->lock));
   
   /* handle lookup here, malloc and assign to copy. */
   struct sr_nat_mapping *copy = NULL;
   sr_nat_mapping_t *mappingWalker;
      
   for (mappingWalker = nat->mappings; mappingWalker != NULL; mappingWalker = mappingWalker->next)
   {
      if ((mappingWalker->type == type) && (mappingWalker->ip_int == ip_int)
         && (mappingWalker->aux_int == aux_int))
      {
         mappingWalker->last_updated = time(NULL);
         copy = malloc(sizeof(sr_nat_mapping_t));
         memcpy(copy, mappingWalker, sizeof(sr_nat_mapping_t));
         break;
      }
   }
   
   pthread_mutex_unlock(&(nat->lock));
   return copy;
}

/* Insert a new mapping into the nat's mapping table.
 Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int,
   sr_nat_mapping_type type)
{
   pthread_mutex_lock(&(nat->lock));
   
   /* handle insert here, create a mapping, and then return a copy of it */
   struct sr_nat_mapping *mapping = malloc(sizeof(sr_nat_mapping_t));
   struct sr_nat_mapping *copy = malloc(sizeof(sr_nat_mapping_t));
   
   if (type == nat_mapping_icmp)
   {
      LOG_MESSAGE("Creating ICMP mapping from %u.%u.%u.%u:%u to %u\n", (ip_int >> 24) & 0xFF, 
         (ip_int >> 16) & 0xFF, (ip_int >> 8) & 0xFF, ip_int & 0xFF, aux_int, nat->nextIcmpIdentNumber);
      mapping->aux_ext = nat->nextIcmpIdentNumber;
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
      LOG_MESSAGE("Creating TCP mapping from %u.%u.%u.%u:%u to %u\n", (ip_int >> 24) & 0xFF, 
         (ip_int >> 16) & 0xFF, (ip_int >> 8) & 0xFF, ip_int & 0xFF, aux_int, nat->nextTcpPortNumber);
      mapping->aux_ext = nat->nextTcpPortNumber;
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
   mapping->conns = NULL; /* TODO */
   
   /* Add mapping to the front of the list. */
   mapping->next = nat->mappings;
   nat->mappings = mapping;
   
   memcpy(copy, mapping, sizeof(sr_nat_mapping_t));
   
   pthread_mutex_unlock(&(nat->lock));
   return copy;
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
      
      free(natMapping);
   }
}
