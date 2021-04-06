/*
    NAST

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

/*
   Common functions
                                    */

#include "include/nast.h"
#include <stdarg.h>

/* run complex plugins here */

/* r: reset a connection
 * s: follow tcp stream
 * M: multi_scanner
 * S: single port_scanner
 */

int runcplx (char what, char *dev, int l)
{
   u_long ip_dst, ip_src;
   u_short port_dst, port_src;
   libnet_plist_t plist, *plist_p;
   char buff[50];
   u_short i;
   libnet_t *L;
   char errbuf[PCAP_ERRBUF_SIZE];

   i = 0;
   if ((L = libnet_init (LIBNET_LINK, NULL, errbuf))==NULL)
     {
	w_error(1,"Error loading libnet core!\n");
     }

   switch (what)
     {
      case 'r':
      	/* don't touch here */
	error:
	puts ("Type connection extremes");
	puts ("------------------------");
	do
	  {
	     if (i) printf ("Cannot resolve input address, type again!\n");
	     printf ("1 ip / hostname : ");
	     fgets (buff, 50, stdin);
	     if ((ip_src = libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
	       {
		  w_error(1,"Error: %s\n", libnet_geterror(L));
	       }
	     i ++;
	  }
	while (ip_src == -1);

	i = 0;
	printf ("1 port (0 to autodetect) : ");
	fgets (buff, 50, stdin);
	port_src = atoi(buff);
	do
	  {
	     if (i) printf ("Cannot resolve input address, type again!\n");
	     printf ("2 ip / hostname : ");
	     fgets (buff, 50, stdin);
	     if ((ip_dst = libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
	       {
		  w_error(1, "Error: %s\n", libnet_geterror(L));
	       }

	     i++;
	  }
	while (ip_dst == -1);

	printf ("2 port (0 to autodetect) : ");
	fgets (buff, 50, stdin);
	port_dst = atoi(buff);
	if (!port_src && !port_dst)
	  {
	     printf ("\nOnly one port can be zero\n");
	     i=0;
	     goto error;
	  }

	printf ("\n");

	/* demonize */
	if (demonize)
	  printf ("Is very useless demonize me now! Omit\n\n");

	rst (dev, ip_src, ip_dst, port_src, port_dst);
	break;

      case 's':
	puts ("Type connection extremes");
	puts ("------------------------");
	do
	  {
	     if (i) printf ("Cannot resolve input address, type again!\n");
	     printf ("1st ip : ");
	     fgets (buff, 50, stdin);
	     if ((ip_src = libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
	       {
		  w_error(1,"Error: %s\n", libnet_geterror(L));
	       }
	     i ++;
	  }
	while (ip_src == -1);
	printf ("1st port : ");
	fgets (buff, 50, stdin);
	port_src = atoi(buff);

	i = 0;
	do
	  {
	     if (i) printf ("Cannot resolve input address, type again!\n");
	     printf ("2nd : ");
	     fgets (buff, 50, stdin);
	     if ((ip_dst = libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
	       {
		  w_error(1, "Error: %s\n", libnet_geterror(L));
	       }

	     i++;
	  }
	while (ip_dst == -1);
	printf ("2nd port : ");
	fgets (buff, 50, stdin);
	port_dst = atoi(buff);

	printf ("\n");

	/* demonize */
	if (demonize)
	  bkg();

	stream (dev, ip_src, ip_dst, port_src, port_dst,l);
	break;

      case 'S':
	printf("Port Scanner extremes\n");
	printf("Insert IP to scan   : ");
	fgets(buff ,50 ,stdin);
	if ((ip_dst = libnet_name2addr4(L, dn(buff), LIBNET_RESOLVE))==-1)
	  {
	     w_error(1, "Error: %s\n", libnet_geterror(L));
	  }
	do
	  {
	     bzero(buff,50);
	     printf("Insert Port range   : ");
	     fgets(buff ,50 ,stdin);
	  }
	while (atoi(dn(buff)) < 1 || atoi(dn(buff)) > 65536);
	plist_p = &plist;
	if (libnet_plist_chain_new(L, &plist_p, dn(buff)) == -1)
	  {
	     w_error(1, "Bad token in port list: %s\n",libnet_geterror(L));
	  }
	printf("\n");

	/* demonize */
	if (demonize)
	  printf ("Is very useless demonize for single portscan! Omit\n\n");

	port(dev,ip_dst,plist_p,l);
	break;

      case 'M':
	printf("Port Scanner extremes\n");
	do
	  {
	     printf("Insert Port range   : ");
	     fgets(buff ,50 ,stdin);
	  }
	while (atoi(dn(buff)) < 1 || atoi(dn(buff)) > 65536);
	plist_p = &plist;
	if (libnet_plist_chain_new(L, &plist_p, dn(buff) )== -1)
	  {
	     w_error(1, "Bad token in port list: %s\n",libnet_geterror(L));
	  }
	printf("\n");

	/* demonize */
	if (demonize)
	  bkg();

	mhport (dev,plist_p,l);
	break;
     }

   if (L) libnet_destroy(L);

   return 0;
}

/* delete \n */
char * dn (char * s)
{
   if (s[strlen(s)-1]=='\n')
     s[strlen(s)-1]='\0';
   return s;
}

/* open a file to log to */
void openfile(void)
{
   if ((logd = (fopen(logname,"w"))) == NULL)
     {
	w_error(1, "Unable to open logfile descriptor: %s\n\n", strerror(errno));
     }
}

/* signal handler */
void sigexit()
{
#ifdef HAVE_LIBNCURSES
# include <ncurses.h>
   if(graph)
     {
	endwin();
	printf("Thank you for using NAST\n\n");
	exit(0);
     }

#endif

   if (!tr && sniff_glob)
     {
	if (pcap_stats(descr,&statistic) < 0)
	  w_error(1, "Error: pcap_stats: %s\n", pcap_geterr(descr));
	else
	  {
	     printf("\n\nPackets Received:\t\t%d\n", statistic.ps_recv);
	     printf("Packets Dropped by kernel:\t%d\n", statistic.ps_drop);
	  }
     }

   if (tl)
     pcap_dump_close(dumper);

   if (logd) 
     fclose(logd);

   exit(0);
}

/* demonize process */
void bkg(void)
{
   if (fork()) exit(0);
   printf ("\nRunning in background with PID %d\n", getpid());
   puts("\n");
   fclose (stdout);
}

/* convert u_char to "##:##:##...##" format */
char * nast_hex_ntoa (u_char *s)
{
   char *r = calloc (18, sizeof (char));

   sprintf (r, "%02X:%02X:%02X:%02X:%02X:%02X",
	    s[0], s[1], s[2], s[3], s[4], s[5]);

   return r;
}

/* convert u_char[4] to "###.###.###.###" format */
char * nast_atoda (u_char *s) /* array to dot array */
{
   char *r = calloc (16, sizeof (char));

   sprintf (r, "%d.%d.%d.%d", s[0], s[1], s[2], s[3]);

   return r;
}

void n_print(char *wins, int y, int x, int lg, char *string, ...)
{
   char msg[2048];
   int n;
   va_list ap;

   va_start(ap, string);
   n = vsnprintf(msg, 2048, string, ap);
   va_end(ap);

   if(!graph && !lg)
     {
	printf("%s",msg);
	fflush(NULL);
     }

   if(!graph && lg)
     {
	fprintf(logd,"%s\n",msg);
	printf("%s",msg);
	fflush(NULL);
     }

#ifdef HAVE_LIBNCURSES
   if(graph && lg)
     {
	fprintf(logd,"%s",msg);
	ng_print(wins,y,x,msg);
     }

   if(graph && !lg)
     ng_print(wins,y,x,msg);
#endif
}

