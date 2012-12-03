/*-----------------------------------------------------------------------------
 * File: sr_main.c
 * Date: Fall 2009
 * Authors: Guido Apanzeller, Vikram Vijayaraghaven, Martin Casado
 * Contact: dgu@cs.stanford.edu
 *
 * Based on many generations of sr clients including the original c client
 * and bert.
 *
 * Description:
 *
 * Driver file for sr
 *
 *---------------------------------------------------------------------------*/

/*
 *-----------------------------------------------------------------------------
 * Include Files
 *-----------------------------------------------------------------------------
 */

#ifdef _SOLARIS_
#define __EXTENSIONS__
#endif /* _SOLARIS_ */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <stdbool.h>

#ifdef _LINUX_
#include <getopt.h>
#endif /* _LINUX_ */

#include "sr_dumper.h"
#include "sr_router.h"
#include "sr_rt.h"

/*
 *-----------------------------------------------------------------------------
 * Private Defines
 *-----------------------------------------------------------------------------
 */

#define VERSION_INFO "VNS sr stub code revised 2009-10-14 (rev 0.20)"
#define DEFAULT_PORT 8888
#define DEFAULT_HOST "vrhost"
#define DEFAULT_SERVER "localhost"
#define DEFAULT_RTABLE "rtable"
#define DEFAULT_TOPO 0
#define DEFAULT_ICMP_TIMEOUT  (60)
#define DEFAULT_TCP_ESTABLISHED_TIMEOUT   (7440)
#define DEFAULT_TCP_TRANSITORY_TIMEOUT    (300)

/*
 *-----------------------------------------------------------------------------
 * Private Macros
 *-----------------------------------------------------------------------------
 */

/*
 *-----------------------------------------------------------------------------
 * Private Types
 *-----------------------------------------------------------------------------
 */

typedef struct sr_command_args
{
   char *host;
   char *user;
   char *server;
   char *rtable;
   char *template;
   unsigned int port;
   unsigned int topo;
   char *logfile;
   bool natEnabled;
   unsigned int icmpQueryTimeout;
   unsigned int tcpEstablishedTimeout;
   unsigned int tcpTransitioryTimeout;
} sr_command_args_t;

/*
 *-----------------------------------------------------------------------------
 * Private variables & Constants
 *-----------------------------------------------------------------------------
 */

static const sr_command_args_t sr_default_config = 
{ 
   DEFAULT_HOST, /* host */ 
   0, /* user */
   DEFAULT_SERVER, /* server */
   DEFAULT_RTABLE, /* routing table */
   NULL, /* template*/
   DEFAULT_PORT, /* port */
   DEFAULT_TOPO, /* topo */
   0, /* logfile */
   false, /* natEnabled */
   DEFAULT_ICMP_TIMEOUT, /* icmpQueryTimeout */    
   DEFAULT_TCP_ESTABLISHED_TIMEOUT, /* tcpEstablishedTimeout */
   DEFAULT_TCP_TRANSITORY_TIMEOUT /* tcpTransitioryTimeout */
};

#ifdef _CYGWIN_
extern char* __attribute__((dllimport)) optarg;
#else
extern char* optarg;
#endif

/*
 *-----------------------------------------------------------------------------
 * Private Function Declarations
 *-----------------------------------------------------------------------------
 */

static void usage(char*);
static void sr_init_instance(struct sr_instance*);
static void sr_destroy_instance(struct sr_instance*);
static void sr_set_user(struct sr_instance*);
static void sr_load_rt_wrap(struct sr_instance* sr, char* rtable);

/*
 *-----------------------------------------------------------------------------
 * Public Function Definitions
 *-----------------------------------------------------------------------------
 */

int main(int argc, char **argv)
{
   int c;
   sr_command_args_t cmdArgs = sr_default_config;
   struct sr_instance sr;
   
   printf("Using %s\n", VERSION_INFO);
   
   while ((c = getopt(argc, argv, "hns:v:p:u:t:r:l:T:I:E:R:")) != EOF)
   {
      switch (c)
      {
         case 'h':
            usage(argv[0]);
            exit(0);
            break;
         case 'p':
            cmdArgs.port = atoi((char *) optarg);
            break;
         case 't':
            cmdArgs.topo = atoi((char *) optarg);
            break;
         case 'v':
            cmdArgs.host = optarg;
            break;
         case 'u':
            cmdArgs.user = optarg;
            break;
         case 's':
            cmdArgs.server = optarg;
            break;
         case 'l':
            cmdArgs.logfile = optarg;
            break;
         case 'r':
            cmdArgs.rtable = optarg;
            break;
         case 'T':
            cmdArgs.template = optarg;
            break;
         case 'n':
            cmdArgs.natEnabled = true;
            break;
         case 'I':
            cmdArgs.icmpQueryTimeout = atoi(optarg);
            break;
         case 'E':
            cmdArgs.tcpEstablishedTimeout = atoi(optarg);
            break;
         case 'R':
            cmdArgs.tcpTransitioryTimeout = atoi(optarg);
            break;
         default:
            /* This case should be caught for us by getopt, but it's good form 
             * to have a default in every switch statement. */
            break;
      } /* switch */
   } /* -- while -- */
   
   /* -- zero out sr instance -- */
   sr_init_instance(&sr);
   
   /* -- set up routing table from file -- */
   if (cmdArgs.template == NULL)
   {
      sr.template_name[0] = '\0';
      sr_load_rt_wrap(&sr, cmdArgs.rtable);
   }
   else
      strncpy(sr.template_name, cmdArgs.template, 30);
   
   sr.topo_id = cmdArgs.topo;
   strncpy(sr.host, cmdArgs.host, 32);
   
   if (!cmdArgs.user)
   {
      sr_set_user(&sr);
   }
   else
   {
      strncpy(sr.user, cmdArgs.user, 32);
   }
   
   /* -- set up file pointer for logging of raw packets -- */
   if (cmdArgs.logfile != NULL)
   {
      sr.logfile = sr_dump_open(cmdArgs.logfile, 0, PACKET_DUMP_SIZE);
      if (!sr.logfile)
      {
         fprintf(stderr, "Error opening up dump file %s\n", cmdArgs.logfile);
         exit(1);
      }
   }
   
   Debug("Client %s connecting to Server %s:%d\n", sr.user, cmdArgs.server, cmdArgs.port);
   if (cmdArgs.template)
      Debug("Requesting topology template %s\n", cmdArgs.template);
   else
      Debug("Requesting topology %d\n", cmdArgs.topo);
   
   /* connect to server and negotiate session */
   if (sr_connect_to_server(&sr, cmdArgs.port, cmdArgs.server) == -1)
   {
      fprintf(stderr, "Error opening up connection to %s:%u\n", cmdArgs.server, cmdArgs.port);
      return 1;
   }
   
   if ((cmdArgs.template != NULL) && (strcmp(cmdArgs.rtable, "rtable.vrhost") == 0))
   {
      /* we've recv'd the rtable now, so read it in */
      Debug("Connected to new instantiation of topology template %s\n", cmdArgs.template);
      sr_load_rt_wrap(&sr, "rtable.vrhost");
   }
   else
   {  
      /* Read from specified routing table */
      sr_load_rt_wrap(&sr, cmdArgs.rtable);
   }
   
   if (cmdArgs.natEnabled)
   {
      sr.nat = malloc(sizeof(sr_nat_t));
      assert(sr.nat);
      
      sr_nat_init(sr.nat);
      
      sr.nat->icmpTimeout = cmdArgs.icmpQueryTimeout;
      sr.nat->tcpEstablishedTimeout = cmdArgs.tcpEstablishedTimeout;
      sr.nat->tcpTransitoryTimeout = cmdArgs.tcpTransitioryTimeout;
   }
   else
   {
      sr.nat = NULL;
   }

   /* call router init (for arp subsystem etc.) */
   sr_init(&sr);
   
   /* -- whizbang main loop ;-) */
   while (sr_read_from_server(&sr) == 1)
   {
   }
   
   sr_destroy_instance(&sr);
   
   return 0;
}/* -- main -- */

/*
 *-----------------------------------------------------------------------------
 * Private Function Definitions
 *-----------------------------------------------------------------------------
 */

/*-----------------------------------------------------------------------------
 * Method: usage(..)
 * Scope: local
 *---------------------------------------------------------------------------*/

static void usage(char* argv0)
{
   printf("Simple Router and NAT Client\n");
   printf("Format: %s [-h] [-n] [-v host] [-s server] [-p port] \n", argv0);
   printf("           [-T template_name] [-u username] \n");
   printf("           [-t topo id] [-r routing table] \n");
   printf("           [-l log file] [-I ICMP Timeout] \n");
   printf("           [-E TCP Established Timeout] [-R TCP Transitory Timeout] \n");
   printf("   defaults server=%s port=%d host=%s  \n", DEFAULT_SERVER, DEFAULT_PORT, DEFAULT_HOST);
} /* -- usage -- */

/*-----------------------------------------------------------------------------
 * Method: sr_set_user(..)
 * Scope: local
 *---------------------------------------------------------------------------*/

void sr_set_user(struct sr_instance* sr)
{
   uid_t uid = getuid();
   struct passwd* pw = 0;
   
   /* REQUIRES */
   assert(sr);
   
   if ((pw = getpwuid(uid)) == 0)
   {
      fprintf(stderr, "Error getting username, using something silly\n");
      strncpy(sr->user, "something_silly", 32);
   }
   else
   {
      strncpy(sr->user, pw->pw_name, 32);
   }
   
} /* -- sr_set_user -- */

/*-----------------------------------------------------------------------------
 * Method: sr_destroy_instance(..)
 * Scope: Local
 *
 *
 *----------------------------------------------------------------------------*/

static void sr_destroy_instance(struct sr_instance* sr)
{
   /* REQUIRES */
   assert(sr);
   
   if (sr->logfile)
   {
      sr_dump_close(sr->logfile);
   }
   
   /*
    fprintf(stderr,"sr_destroy_instance leaking memory\n");
    */
} /* -- sr_destroy_instance -- */

/*-----------------------------------------------------------------------------
 * Method: sr_init_instance(..)
 * Scope: Local
 *
 *
 *----------------------------------------------------------------------------*/

static void sr_init_instance(struct sr_instance* sr)
{
   /* REQUIRES */
   assert(sr);
   
   sr->sockfd = -1;
   sr->user[0] = 0;
   sr->host[0] = 0;
   sr->topo_id = 0;
   sr->if_list = 0;
   sr->routing_table = 0;
   sr->logfile = 0;
   sr->nat = NULL;
} /* -- sr_init_instance -- */

/*-----------------------------------------------------------------------------
 * Method: sr_verify_routing_table()
 * Scope: Global
 *
 * make sure the routing table is consistent with the interface list by
 * verifying that all interfaces used in the routing table actually exist
 * in the hardware.
 *
 * RETURN VALUES:
 *
 *  0 on success
 *  something other than zero on error
 *
 *---------------------------------------------------------------------------*/

int sr_verify_routing_table(struct sr_instance* sr)
{
   struct sr_rt* rt_walker = 0;
   struct sr_if* if_walker = 0;
   int ret = 0;
   
   /* -- REQUIRES --*/
   assert(sr);
   
   if ((sr->if_list == 0) || (sr->routing_table == 0))
   {
      return 999; /* doh! */
   }
   
   rt_walker = sr->routing_table;
   
   while (rt_walker)
   {
      /* -- check to see if interface exists -- */
      if_walker = sr->if_list;
      while (if_walker)
      {
         if (strncmp(if_walker->name, rt_walker->interface, sr_IFACE_NAMELEN) == 0)
         {
            break;
         }
         if_walker = if_walker->next;
      }
      if (if_walker == 0)
      {
         /* -- interface not found! -- */
         ret++;
      } 
      
      rt_walker = rt_walker->next;
   } /* -- while -- */
   
   return ret;
} /* -- sr_verify_routing_table -- */

static void sr_load_rt_wrap(struct sr_instance* sr, char* rtable)
{
   if (sr_load_rt(sr, rtable) != 0)
   {
      fprintf(stderr, "Error setting up routing table from file %s\n", rtable);
      exit(1);
   }
   
   printf("Loading routing table\n");
   printf("---------------------------------------------\n");
   sr_print_routing_table(sr);
   printf("---------------------------------------------\n");
}
