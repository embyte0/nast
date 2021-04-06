/*
    nast

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include "include/nast.h"
#include <sys/utsname.h>

#ifdef HAVE_GETOPT
# include <getopt.h>
#else
# include "missing/getopt.h"
#endif

void usage(char *name);

int main(int argc,char **argv)
{
   char *dev, *app;
   char *filter, *buffer, ldname[50];
   char errbuf[PCAP_ERRBUF_SIZE];
   extern char *optarg;
   int option, option_index;
   u_long anip;
   libnet_t *L;
   struct utsname buf;
   
   static u_short ports[] =
     {
	21, 22, 23,  25, 43, 53, 79, 80, 110, 119, 143, 220, 513, 514
     };

   struct FLAGSTRUCT
     {
	u_short promisc;
	u_short l;
	u_short data;
	u_short hex;
	u_short f;
	u_short ps;
	u_short gw;
	u_short rt;
	u_short lk;
	u_short pr;
	u_short st;
	u_short mp;
	u_short banner;
	u_short maplan;
	u_short c_arp;
	u_short ld;
	u_short bytecount;
	u_short ncurses;
	u_short tcpdlog;
	u_short tcpdread;
     }
   flags;
   static struct option long_options[] =
     {
	  { "help",       0, NULL, 'H'},
	  { "promisc",    0, NULL, 'p'},
	  { "ascii-data", 0, NULL, 'd'},
	  { "filter",     1, NULL, 'f'},
	  { "interface",  1, NULL, 'i'},
	  { "ascii-hex-data", 0, NULL, 'x'},
	  { "log-file",   1, NULL, 'l'},
	  { "check-sniffers",  1, NULL, 'P'},
	  { "host-list",  0, NULL, 'm'},
	  { "tcp-stream", 0, NULL, 's'},
	  { "find-gateway",   0, NULL, 'g'},
	  { "reset-connection", 0, NULL, 'r'},
	  { "port-scanner",   0, NULL, 'S'},
	  { "multi-port-scanner", 0, NULL, 'M'},
	  { "find-link",  0, NULL, 'L'},
	  { "daemon-banner",  0, NULL, 'b'},
	  { "check-arp-poisoning", 0, NULL, 'c'},
	  { "ncurses",    0, NULL, 'G'},
	  { "daemon",     0, NULL, 'B'},
	  { "version",    0, NULL, 'V'},
	  { "ld",         1, NULL, '\0'},
	  { "byte-counting", 1, NULL, 'C'},
	  { "tcpdump-log", 1, NULL, 'T'},
	  { "tcpdump-log-read", 1, NULL , 'R'},
	  { 0, 0, 0, 0}
     };

   printf ("\n%sNast V. %s%s\n\n", BOLD, PACKAGE_VERSION, NORMAL);

   /* check permissions */
   if (getuid() || getgid())
     {
        fprintf(stderr, "You must be root, Sorry\n\n");
        return -1;
     }

   /* finding a suitable device */
   dev = pcap_lookupdev(errbuf);
   if (dev==NULL)
     {
	fprintf (stderr, "Error: can't find a suitable interface to use: %s\n", errbuf);
	return -1;
     }
   
   /*
   res = pcap_findalldevs(&devices, errbuf);
   if (res < 1 && 0)
     {
	fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
	return -1;
     }

     try to find the device 
   for (devc = devices; devc; devc = devc->next)
     {
	if (!strcmp(devc->name,"any"))
	  continue;
	if (devc->flags & PCAP_IF_LOOPBACK)
	  {
	     strcpy(dev,devc->name);
	     continue;
	  }
	else
	  {
	     strcpy(dev,devc->name);
	     break;
	  }
     }

   pcap_freealldevs(devices);
   */
   
   if  ((L = libnet_init (LIBNET_LINK, dev, errbuf))==NULL)
     {
	fprintf(stderr, "Error: can't initialize libnet engine: %s", errbuf);
	fprintf(stderr, "Have you activate a non-loopback iface? (man ifconfig)\n");
	exit(-1);
     }

   line_s = row_s = cont = lg = 0;
   option_index = 0;
   anip = 0;
   sniff_glob = 0;
   memset (&flags, 0, sizeof (struct FLAGSTRUCT));
   flags.promisc = 1;  /*default is promisc */
   logname = filter = buffer = tcpdl = NULL;
   strcpy(ldname,"NULL");

   /* get global time */
   tm = time(NULL);
   strftime(timed,60,"%T",localtime(&tm));

   while ((option=getopt_long(argc, argv, "mi:hHpdxl:f:C:P:R:T:sgrSLbMcGBV0", long_options, &option_index)) !=EOF)
     switch(option)
       {
        case 'h':
	case 'H':
	  usage(argv[0]);
	  break;
        case 'i':
	  (app=optarg);
	  strcpy(dev,app);
	  break;
	case 'l': /* log to file */
	  flags.l=1;
	  lg = 1;
	  (logname = optarg);
	  break;
        case 'p':
	  flags.promisc=0;
	  break;
        case 'd':
	  flags.data=1;
	  break;
        case 'x':
	  flags.hex=1;
	  break;
	case 'f':
	  flags.f=1;
	  (filter = optarg);
	  break;
	case 'P':
	  flags.ps=1;
	  if (dev!=NULL) /* we have other interface that is not lo */
	    if (strcmp (optarg, "all")) /* != all */
	      {
		 anip = libnet_name2addr4(L, optarg, LIBNET_RESOLVE);
		 if (anip==-1)
		   {
		      libnet_destroy(L);
		      w_error(1, "Error: cannot resolve %s\n\n", optarg);
		   }
	      }
	      /* if optarg=all -> anip = 0 */
	  break;
	case 's':
	  flags.st=1;
	  break;
	case 'g':
	  flags.gw=1;
	  break;
	case 'r':
	  flags.rt=1;
	  break;
	case 'S':
	  flags.pr = 1;
	  break;
	case 'L':
	  flags.lk=1;
	  break;
	case 'b':
	  flags.banner=1;
	  break;
	case 'M':
	  flags.mp=1;
	  break;
	case 'm':
	  flags.maplan=1;
	  break;
	case 'c':
	  flags.c_arp=1;
	  break;
	case 'B':
	  demonize=1;
	  break;
	case 'C':
	  flags.bytecount=1;
	  (filter = optarg);
	  break;
	case 'T':
	  flags.tcpdlog=1;
	  tl=1;
	  (tcpdl = optarg);
	  break;
	case 'R':
	  flags.tcpdread=1;
	  tr=1;
	  (tcpdl = optarg);
	  break;
	case 'G':
#ifdef HAVE_LIBNCURSES
	  flags.ncurses=1;
	  graph=1;
#else
	  printf ("You have not compiled ncurses interface support!\n");
	  printf ("You *must* install libncurses and recompile nast\n");
	  printf ("\nDownload it from official web site: http://www.gnu.org/software/ncurses/ncurses.html\n");
	  printf ("or install your distribution binary package (remember to install also the -devel package)\n\n");
	  return -1;
#endif
	  break;
	case 'V':
	  printf ("%s2003-2004 (c) Embyte & Snifth\n", BOLD);
	  if (uname(&buf)!=-1)
	    {
	       printf ("Running on %s %s (%s)\n", buf.sysname, buf.release, buf.machine);
	    }
	  printf ("See http://nast.berlios.de%s\n\n", NORMAL);
	  exit(0);

	/* only long options */
	case '\0':
	  if (!strcmp(long_options[option_index].name,"ld"))
	    strcpy(ldname,optarg);
	  break;
	default:
	  usage(argv[0]);
	  break;
       }
   /* END OF ARGS SWITCH */

   if (dev==NULL)
     {
	fprintf(stderr, "Cannot find a suitable network interface!\n");
	fprintf(stderr, "Check you connection (will ifconfig help you?)\n\n");
	libnet_destroy(L);
	return -1;
     }

   /* destroy libnet_t *L */
   libnet_destroy(L);

   /* signal handlers */
   signal(SIGKILL, sigexit);
   signal(SIGQUIT, sigexit);
   signal(SIGTERM, sigexit);
   signal(SIGINT, sigexit);

   /* Do we want a log? */
   if (flags.l == 0)
     logd = stdout;

   /* RUN PLUGIN ONLY HERE! */
#ifdef HAVE_LIBNCURSES
   if (flags.ncurses) return main_graph();
#endif
   if (flags.banner) return mport (dev, ports, flags.l);
   if (flags.maplan)
     {
	if (map_lan(dev, 1, NULL)==NULL) return 0;
	else return -1;
     }
   if (flags.c_arp) return car (dev,flags.l);
   if (flags.gw) return fgw (dev);
   if (flags.lk) return flink (dev);
   if (flags.rt) return runcplx ('r', dev, flags.l);
   if (flags.st) return runcplx ('s', dev, flags.l);
   if (flags.mp) return runcplx ('M', dev ,flags.l);
   if (flags.pr) return runcplx ('S', dev, flags.l);
   if (flags.ps) return psearch (dev, anip, flags.l);
   if (flags.bytecount) return run_bc (dev, filter);
   /* END OF PLUG_INS */

   /* SNIFF HERE */
   sniff_glob = 1;
   return run_sniffer (flags.promisc, flags.data, flags.hex, flags.f, flags.l, flags.tcpdlog, flags.tcpdread, filter, dev, ldname);
}

void usage(char *name)
{

   printf("\n%sUsage:%s nast [options]\n\n", BOLD, NORMAL);

   printf("%sSniffer options:%s\n", BOLD, NORMAL);
   printf("  -i, --interface                    Interface\n");
   printf("                                      if not specified will be autodetected\n");
   printf("  -p, --promisc                      Set promisc mode (set by default)\n");
   printf("  -d, --ascii-data                   Print ascii data\n");
   printf("  -x, --ascii-hex-data               Print ascii-hex data\n");
   printf("  -f, --filter <\"filter\">            Apply filter\n");
   printf("      --ld <filename>                Log sniffed data to <filename> (only payload)\n");
   printf("                                      use -l to log all packets too, useful with -B\n");
   printf("  -T, --tcpdump-log <filename>       Log all packets in tcpdump format\n");
   printf("  -R, --tcpdump-log-read <filename>  Read all packets saved in tcpdump format\n");
   printf("                                      from saved file\n");

   printf("\n%sAnalyzer options:%s\n", BOLD, NORMAL);
   printf("  -P, --check-sniffers <ip>          Check for remote sniffers,\n");
   printf("                                      use -P all to query all network NIC\n");
   printf("  -m, --host-list                    Build hosts list of the LAN\n");
   printf("  -s, --tcp-stream                   Follow TCP Stream\n");
   printf("  -g, --find-gateway                 Try to find a valid gateway\n");
   printf("  -r, --reset-connection             Reset a connection (use with caution)\n");
   printf("  -S, --port-scanner                 Syn style port scanner\n");
   printf("  -M, --multi-port-scanner           Port scanner all LAN's host (SYN style)\n");
   printf("  -L, --find-link                    Try to resolve if there's a hub or a switch in LAN\n");
   printf("  -b, --daemon-banner                Catch daemon banner for the hosts in LAN\n");
   printf("  -c, --check-arp-poisoning          Verify if someone is making arp-poisoning\n");
   printf("                                      comparing arp responses\n");
   printf("  -C, --byte-counting <\"filter\">     Apply traffic counting to \"filter\"\n");
   printf("                                      use -C any to disable filter\n");

   printf("\n%sGraphical options:%s\n", BOLD, NORMAL);
   printf("  -G, --ncurses                      Ncurses menu:\n");
   printf("                                      this option is available only if you\n");
   printf("                                      have compiled nast with ncurses support,\n");
   printf("                                      this is the default if I found libncurses\n");
   printf("                                      installed in your *unix-box\n");

   printf("\n%sOther options:%s\n", BOLD, NORMAL);
   printf("  -l, --log-file <filename>          Log reports to file (work with many features)\n");
   printf("  -B, --daemon                       Run in background like demon:\n");
   printf("                                      usefull for sniffer/stream/arp_control logging\n");
   printf("  -V, --version                      Show version information\n");
   printf("  -h, --help                         Print this help\n");
   printf("\n");

   exit(0);
}

