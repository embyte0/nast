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

#include "n_nast.h"

#ifdef HAVE_LIBNCURSES

# define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
# define CTRLD 	4

void *n_sniff(void *threadid);
void *t_arp(void *threadarg);
int check_filter(char *filt);
int s_select(void);
int r_select(void);

int sport,dport;
u_long ip_src, ip_dst;
libnet_t *L = NULL;
libnet_plist_t plist, *plist_p;

static u_short ports[] =
{
   21, 22, 23, 25, 43, 53, 79, 80, 110, 119, 143, 220, 513, 514
};

char *choices[] =
{
   "  (S)niffer  ",
     "  (A)nalyzer  ",
     "  (O)ptions  ",
     (char *)NULL,
};

char *sniffer[] =
{
   "Start Sniff            ",
     "Stop Sniff             ",
     "Filter                 ",
     "Promisc                ",
     "ASCII                  ",
     "HEX                    ",
     "Log Payload            ",
     "Log TCPDUMP format     ",
     "Read TCPDUMP File      ",
     "Log all packets        ",
     (char *)NULL,
};

char *analyzer[] =
{
   "Check Sniffers          ",
     "Hosts List              ",
     "TCP Stream              ",
     "Find Gateway            ",
     "Reset Connection        ",
     "Port Scanner            ",
     "Multi Port Scanner      ",
     "Find Link               ",
     "Daemon Banner           ",
     "Check ARP Poinsoning    ",
     "Byte Counting           ",
     (char *)NULL,
};

char *options[] =
{
   "Interface        ",
     "Log Report       ",
     "Daemonize        ",
     "Stop Application ",
     "Version          ",
     "Help             ",
     "Exit             ",
     (char *)NULL,
};

void nmenu()
{
   ITEM **my_items;
   int ris;
   int n_choices, i;

   ris = 0;

   n_choices = ARRAY_SIZE(choices);
   my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));
   for(i = 0; i < n_choices; ++i)
     my_items[i] = new_item(choices[i], choices[i]);

   my_nmenu = new_menu((ITEM **)my_items);

   my_nmenu_win = newwin(3,COLS, 3, 0);
   keypad(my_nmenu_win, TRUE);
   wbkgd(my_nmenu_win,COLOR_PAIR(5));

   if(flg==0)
     {
	menu_opts_on(my_nmenu, O_SHOWDESC);
	mvwprintw(my_nmenu_win,1,1,"   (S)niffer       (A)nalyzer      (O)ptions");
     }
   else menu_opts_off(my_nmenu, O_SHOWDESC);
   mvwprintw(my_nmenu_win,1,COLS-8,"(F1)");

   set_menu_win(my_nmenu, my_nmenu_win);
   set_menu_sub(my_nmenu, derwin(my_nmenu_win, 2, COLS-2, 1, 1));

   if(flg==1)
     set_menu_format(my_nmenu, 1, 3);
   set_menu_mark(my_nmenu, " ");

   wcolor_set(my_nmenu_win,3,NULL);
   box(my_nmenu_win, 0, 0);

   post_menu(my_nmenu);
   wrefresh(my_nmenu_win);

}

int sniffer_menu()
{
   ITEM **my_items;
   int c, ris;
   MENU *my_menu;
   WINDOW *my_menu_win;
   int n_choices, i, y;

   y = 1;
   ris = 0;
   mvar = 1;
	/* Create items */
   n_choices = ARRAY_SIZE(sniffer);
   my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));
   for(i = 0; i < n_choices; ++i)
     my_items[i] = new_item(sniffer[i], sniffer[i]);

	/* Crate menu */

   my_menu = new_menu((ITEM **)my_items);

	/* Set menu option not to show the description */
   menu_opts_off(my_menu, O_SHOWDESC);

	/* Create the window to be associated with the menu */
   my_menu_win = newwin(12, 27, 5, 0);
   keypad(my_menu_win, TRUE);
   wbkgd(my_menu_win,COLOR_PAIR(3));

   set_menu_win(my_menu, my_menu_win);
   set_menu_sub(my_menu, derwin(my_menu_win, 11, 25, 1, 1));
   set_menu_mark(my_menu, " ");
   box(my_menu_win, 0, 0);

   post_menu(my_menu);
   wrefresh(my_menu_win);

   while( (c = wgetch(my_menu_win)) != 'q')
     {       switch(c)
       {
	case KEY_UP:
	  y--;
	  if (!y)
	    {
	       menu_driver(my_menu, REQ_LAST_ITEM);
	       y=10;
	    }
	  else
	    menu_driver(my_menu, REQ_UP_ITEM);
	  break;
	case KEY_DOWN:
	  y++;
	  if(y==11)
	    {
	       menu_driver(my_menu, REQ_FIRST_ITEM);
	       y=1;
	    }
	  else
	    menu_driver(my_menu, REQ_DOWN_ITEM);
	  break;
	case KEY_LEFT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-2);
	  break;
	case KEY_RIGHT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-1);
	  break;
	case 10:
	  curr_item = current_item(my_menu);
	  switch(item_index(curr_item))
	    {
	     case 0:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       sniff_glob = 1;
	       pthread_create( &thID[1], NULL, n_sniff , NULL);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;
	     case 1:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       sniff_glob = 0;
	       lg = 0;
	       pthread_cancel (thID[1]);
	       pthread_join (thID[1], NULL);
	       winscroll(princ, -10000);
	       werase(princ->win);
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       promisc = 1;
	       //ascii = hex = f = l = tl = tr = 0;
	       return(0);
	       break;
	     case 2:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert filter to apply (NULL takes no effects):");
	       mvwprintw(pop_up,3,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,5,2);
	       echo();
	       wgetnstr(pop_up, n_filter, 60);
	       noecho();
	       if(strcmp(n_filter, "NULL"))
		 (f=1);
	       else
		 {
		    (f=0);
		    strcpy(n_filter,"NULL");
		 }
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;
	     case 3:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Do you want to set Promisc Mode (y/n)?");
	       mvwprintw(pop_up,3,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,5,2);
	       do
		 {
		    ris=wgetch(pop_up);
		    if (ris == 'y')
		      promisc=1;

		    else if (ris == 'n')
		      promisc=0;

		 }
	       while( ris != 'y' && ris != 'n');
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;

	     case 4:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Do you want to set ASCII data printing (y/n)?");
	       mvwprintw(pop_up,3,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,5,2);
	       do
		 {
		    ris=wgetch(pop_up);
		    if (ris == 'y')
		      ascii=1;

		    else if (ris == 'n')
		      ascii=0;

		 }
	       while( ris != 'y' && ris != 'n');
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;

	     case 5:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Do you want to set ASCII-HEX data printing (y/n)?");
	       mvwprintw(pop_up,3,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,5,2);
	       do
		 {
		    ris=wgetch(pop_up);
		    if (ris == 'y')
		      hex=1;

		    else if (ris == 'n')
		      hex=0;

		 }
	       while( ris != 'y' && ris != 'n');
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;

	     case 6:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert name file for data logging");
	       mvwprintw(pop_up,3,2,"(NULL takes no effects):");
	       mvwprintw(pop_up,4,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,6,2);
	       echo();
	       wgetnstr(pop_up, ldfile, 50);
	       noecho();
	       if (strcmp (ldfile, "NULL")) /* != NULL */
		 (ld=1);
	       else
		 {
		    (ld=0);
		    strcpy(ldfile,"NULL");
		 }
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;

	     case 7:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert name file for packets logging");
	       mvwprintw(pop_up,3,2,"in tcpdump format (NULL takes no effects):");
	       mvwprintw(pop_up,4,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,6,2);
	       echo();
	       wgetnstr(pop_up, tcpdfile, 50);
	       noecho();
	       if (strcmp (tcpdfile, "NULL"))
		 {
		    /* != NULL */
		    (tl=1);
		    tcpdl=tcpdfile;
		 }
	       else
		 {
		    (tl=0);
		    strcpy(tcpdfile,"NULL");
		 }
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;

	     case 8:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert name file for packets reading");
	       mvwprintw(pop_up,3,2,"in tcpdump format (NULL takes no effects):");
	       mvwprintw(pop_up,4,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,6,2);
	       echo();
	       wgetnstr(pop_up, tcpdfile, 50);
	       noecho();
	       if (strcmp (tcpdfile, "NULL"))
		 {
		    /* != NULL */
		    (tr=1);
		    tcpdl=tcpdfile;
		    if(check_pthread() == 1)
		      return(0);
	            sniff_glob = 1;
	            pthread_create( &thID[1], NULL, n_sniff , NULL);
	            delwin(pop_up);
		    redrawscrollwin(princ,0);
		    mvar = 0;
	            return(0);
		 }
	       else
		 {
		    (tr=0);
		    strcpy(tcpdfile,"NULL");
		 }
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;

	     case 9:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert name file for packets logging");
	       mvwprintw(pop_up,3,2,"(NULL takes no effects):");
	       mvwprintw(pop_up,4,2,"Remember to restart sniffer to take option working!");
	       wmove(pop_up,6,2);
	       echo();
	       wgetnstr(pop_up, logfile, 50);
	       noecho();
	       if (strcmp (logfile, "NULL")) /* != NULL */
		 {
		    (l=1);
		    logname = logfile;
		    lg = 1;
		 }
	       else
		 {
		    (l=0);
		    strcpy(logfile,"NULL");
		    lg = 0;
		 }
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       mvar = 0;
	       return(0);
	       break;
	    }

	  break;

       }

	wrefresh(my_menu_win);

     }

	/* Unpost and free all the memory taken up */
   unpost_menu(my_menu);
   free_menu(my_menu);
   for(i = 0; i < n_choices; ++i)
     free_item(my_items[i]);
   werase(my_menu_win);
   wrefresh(my_menu_win);
   mvar = 0;
   return(0);
}

int analyzer_menu()
{

   ITEM **my_items;
   int c;
   MENU *my_menu;
   WINDOW *my_menu_win;
   int n_choices, i, y;
   char errbuf[PCAP_ERRBUF_SIZE];
   char arg[30];
   char buff[50];
   u_long anip;

   y = 1;
   anip = 0;
   mvar = 1;
   L = libnet_init (LIBNET_LINK, NULL, errbuf);
	/* Create items */
   n_choices = ARRAY_SIZE(analyzer);
   my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));
   for(i = 0; i < n_choices; ++i)
     my_items[i] = new_item(analyzer[i], analyzer[i]);

	/* Crate menu */

   my_menu = new_menu((ITEM **)my_items);

	/* Set menu option not to show the description */
   menu_opts_off(my_menu, O_SHOWDESC);

	/* Create the window to be associated with the menu */
   my_menu_win = newwin(13, 28, 5, 15);
   keypad(my_menu_win, TRUE);
   wbkgd(my_menu_win,COLOR_PAIR(3));

   set_menu_win(my_menu, my_menu_win);
   set_menu_sub(my_menu, derwin(my_menu_win, 12, 26, 1, 1));
   set_menu_mark(my_menu, " ");
   box(my_menu_win, 0, 0);

   post_menu(my_menu);
   wrefresh(my_menu_win);

   while((c = wgetch(my_menu_win)) != 'q')
     {       switch(c)
       {
	case KEY_UP:
	  y--;
	  if (!y)
	    {
	       menu_driver(my_menu, REQ_LAST_ITEM);
	       y=11;
	    }
	  else
	    menu_driver(my_menu, REQ_UP_ITEM);
	  break;
	case KEY_DOWN:
	  y++;
	  if (y==12)
	    {
	       menu_driver(my_menu, REQ_FIRST_ITEM);
	       y=1;
	    }
	  else
	    menu_driver(my_menu, REQ_DOWN_ITEM);
	  break;
	case KEY_LEFT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-2);
	  break;
	case KEY_RIGHT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-1);
	  break;
	case 10:	/* Enter */
	  curr_item = current_item(my_menu);
	  switch(item_index(curr_item))
	    {
	     case 0:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       pop_up_win();
	       mvwprintw(pop_up,2,15,"Promisc check");
	       mvwprintw(pop_up,3,2,"Insert IP to scan or \"all\" for all nodes");
	       wmove(pop_up,5,2);
	       echo();
	       wgetnstr(pop_up, arg, 50);
	       noecho();
	       if (strcmp (arg, "all"))
		 {
		    anip = libnet_name2addr4(L, arg, LIBNET_RESOLVE);
		    if (anip==-1)
		      {
			 libnet_destroy(L);
			 if(w_error(0, "Error: cannot resolve %s\n\n", optarg) == -1)
			   return(0);
		      }
		 }
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       psearch (dev, anip, lr);
	       return(0);
	       break;

	     case 1:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       map_lan(dev, 1, NULL);
	       return(0);
	       break;

	     case 2:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       sport = dport = 0;
	       pop_up_win();

	       mvwprintw(pop_up,2,2,"Insert Src IP: (NULL will takes no effects)");
	       wmove(pop_up,3,2);
	       echo();
	       wgetnstr(pop_up, buff, 50);
	       noecho();
	       if (!strcmp(buff,"NULL"))
		 {
		    delwin(pop_up);
		    redrawscrollwin(princ,0);
		    return(0);
		 }

	       if ((ip_src = libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
		 {
		    w_error(0, "Error: %s", libnet_geterror(L));
		    redrawscrollwin(princ,0);
		    return(0);
		 }
	       
	       mvwprintw(pop_up,5,2,"Insert Dst IP: (NULL will takes no effects)");
	       wmove(pop_up,6,2);
	       echo();
	       wgetnstr(pop_up, buff, 50);
	       noecho();

	       if (!strcmp(buff,"NULL"))
		 {
		    delwin(pop_up);
		    redrawscrollwin(princ,0);
		    return(0);
		 }

	       if ((ip_dst = libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
		 {
		    w_error(0, "Error: %s", libnet_geterror(L));
		    redrawscrollwin(princ,0);
		    return 0;
		 }

	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       nmenu();

	       memset(&th_data[0], 0, sizeof(th_data[0]));
		/*passing thread data*/
	       th_data[0].ip_src=ip_src;
	       th_data[0].ip_dst=ip_dst;
	       th_data[0].sport=0;
	       th_data[0].dport=0;
	       strcpy(th_data[0].device,dev);
	       stream_glob = 1;
	       pthread_create(&thID[3], NULL, conn_db ,(void *) &th_data[0]);
	       libnet_destroy(L);
	       s_select();
	       return(0);
	       break;

	     case 3:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       fgw (dev);
	       return(0);
	       break;

	     case 4:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       sport = dport = 0;
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert Src IP: (NULL will takes no effects)");
	       wmove(pop_up,3,2);
	       echo();
	       wgetnstr(pop_up, buff, 50);
	       noecho();
	       if (!strcmp(buff,"NULL"))
		 {
		    delwin(pop_up);
		    redrawscrollwin(princ,0);
		    return(0);
		 }

	       if ((ip_src=libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
		 {
		    w_error(0, "Error: %s", libnet_geterror(L));
		    redrawscrollwin(princ,0);
		    return 0;
		 }

	       mvwprintw(pop_up,5,2,"Insert Dst IP: (NULL will takes no effects)");
	       wmove(pop_up,6,2);
	       echo();
	       wgetnstr(pop_up, buff, 50);
	       noecho();

	       if (!strcmp(buff,"NULL"))
		 {
		    delwin(pop_up);
		    redrawscrollwin(princ,0);
		    return(0);
		 }

	       if ((ip_dst=libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
		 {
		    w_error(0, "Error: %s", libnet_geterror(L));
		    redrawscrollwin(princ,0);
		    return 0;
		 }

	       memset(&th_r_data[0], 0, sizeof(th_r_data[0]));
		/*passing thread data*/
	       th_r_data[0].ip_src=ip_src;
	       th_r_data[0].ip_dst=ip_dst;
	       th_r_data[0].sport=0;
	       th_r_data[0].dport=0;
	       strcpy(th_r_data[0].device,dev);
	       rst_glob = 1;
	       pthread_create( &thID[2], NULL, conn_db_r ,(void *) &th_r_data[0]);
	       libnet_destroy(L);
	       nmenu();
	       r_select();
	       return(0);
	       break;

	     case 5:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       pop_up_win();
	       mvwprintw(pop_up,2,18,"- Port Scanner -");
	       mvwprintw(pop_up,4,2,"Insert IP to scan (NULL will take no effect):");
	       wmove(pop_up,5,2);
	       echo();
	       wgetnstr(pop_up, buff, 50);
	       noecho();
	       if (!strcmp(buff,"NULL"))
		 {
		    delwin(pop_up);
		    redrawscrollwin(princ,0);
		    return(0);
		 }

	       if ((ip_dst = libnet_name2addr4(L, dn (buff), LIBNET_RESOLVE))==-1)
		 {
		    w_error(1, "Error: %s", libnet_geterror(L));
		 }

	       do
		 {
		    mvwprintw(pop_up,7,2,"Insert Port range: ");
		    wmove(pop_up,8,2);
		    echo();
		    wgetnstr(pop_up, buff, 50);
		    noecho();
		 }
	       while (atoi(buff) < 1 || atoi(buff) > 65536);
	       plist_p = &plist;
	       if (libnet_plist_chain_new(L, &plist_p, buff) == -1)
		 {
		    if(w_error(0, "Bad token in port list: %s\n",libnet_geterror(L))==-1)
		      return(0);
		 }
	       delwin(pop_up);
	       nmenu();
	       redrawscrollwin(princ,0);
	       port(dev,ip_dst,plist_p,lr);
	       return(0);
	       break;

	     case 6:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       pop_up_win();
	       mvwprintw(pop_up,2,18,"- MULTI Port Scanner -");
	       mvwprintw(pop_up,4,2,"Insert IP to scan (NULL will take no effect):");
	       do
		 {
		    mvwprintw(pop_up,5,2,"Insert Port range: ");
		    wmove(pop_up,8,2);
		    echo();
		    wgetnstr(pop_up, buff, 50);
		    noecho();
		 }
	       while (atoi(buff) < 1 || atoi(buff) > 65536);
	       plist_p = &plist;
	       if (libnet_plist_chain_new(L, &plist_p, buff) == -1)
		 {
		    if(w_error(0, "Bad token in port list: %s\n",libnet_geterror(L))==-1)
		      return(0);
		 }
	       delwin(pop_up);
	       nmenu();
	       redrawscrollwin(princ,0);
	       mhport (dev,plist_p,lr);
	       return(0);
	       break;

	     case 7:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       flink(dev);
	       return(0);
	       break;

	     case 8:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       mport(dev,ports,lr);
	       return(0);
	       break;

	     case 9:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       memset(&th_arp_data[0], 0, sizeof(th_arp_data[0]));
		/*passing thread data*/
	       th_arp_data[0].lr=lr;
	       strcpy(th_arp_data[0].device,dev);
	       arp_glob = 1;
	       pthread_create( &thID[6], NULL, t_arp ,(void *) &th_arp_data[0]);
	       return(0);
	       break;

	     case 10:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert filter to apply");
	       mvwprintw(pop_up,3,2,"(null or 'any' to disable):");
	       wmove(pop_up,5,2);
	       echo();
	       wgetnstr(pop_up, buff, 50);
	       noecho();
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       bc_glob = 1;
	       run_bc(dev,buff);
	       mvar = 0;
	       return(0);
	       break;

	    }

	  break;

       }

	wrefresh(my_menu_win);

     }

	/* Unpost and free all the memory taken up */
   unpost_menu(my_menu);
   free_menu(my_menu);
   for(i = 0; i < n_choices; ++i)
     free_item(my_items[i]);
   werase(my_menu_win);
   wrefresh(my_menu_win);
   return(0);
}

int options_menu()
{

   ITEM **my_items;
   int c,ris;
   MENU *my_menu;
   WINDOW *my_menu_win;
   int n_choices, i, ok, y;
   char errbuf[PCAP_ERRBUF_SIZE];
   char temp[10];

   ris = ok = 0;
   mvar = y = 1;

	/* Create items */
   n_choices = ARRAY_SIZE(options);
   my_items = (ITEM **)calloc(n_choices, sizeof(ITEM *));
   for(i = 0; i < n_choices; ++i)
     my_items[i] = new_item(options[i], options[i]);

	/* Crate menu */

   my_menu = new_menu((ITEM **)my_items);

	/* Set menu option not to show the description */
   menu_opts_off(my_menu, O_SHOWDESC);

	/* Create the window to be associated with the menu */
   my_menu_win = newwin(9, 21, 5, 31);
   keypad(my_menu_win, TRUE);
   wbkgd(my_menu_win,COLOR_PAIR(3));

   set_menu_win(my_menu, my_menu_win);
   set_menu_sub(my_menu, derwin(my_menu_win, 8, 19, 1, 1));
   set_menu_mark(my_menu, " ");
   box(my_menu_win, 0, 0);

   post_menu(my_menu);
   wrefresh(my_menu_win);

   while((c = wgetch(my_menu_win)) != 'q')
     {       switch(c)
       {
	case KEY_UP:
	  y--;
	  if (!y)
	    {
	       menu_driver(my_menu, REQ_LAST_ITEM);
	       y=7;
	    }
	  else
	    menu_driver(my_menu, REQ_UP_ITEM);
	  break;
	case KEY_DOWN:
	  y++;
	  if (y==8)
	    {
	       menu_driver(my_menu, REQ_FIRST_ITEM);
	       y=1;
	    }
	  else
	    menu_driver(my_menu, REQ_DOWN_ITEM);
	  break;
	case KEY_LEFT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-1);
	  break;
	case KEY_RIGHT:
	  unpost_menu(my_menu);
	  free_menu(my_menu);
	  for(i = 0; i < n_choices; ++i)
	    free_item(my_items[i]);
	  werase(my_menu_win);
	  wrefresh(my_menu_win);
	  return(-2);
	  break;
	case 10:	/* Enter */
	  curr_item = current_item(my_menu);
	  switch(item_index(curr_item))
	    {
	     case 0:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       while(!ok)
		 {
		    pop_up_win();
		    mvwprintw(pop_up,6,5,"Insert the device you want to use, please:");
		    mvwprintw(pop_up,7,5,"   for the default <%s> press enter!",dev);
		    wmove(pop_up,9,23);
		    echo();
		    wgetnstr(pop_up, temp, 10);
		    if(!strcmp(temp,""))
		      strcpy(temp,dev);
		    noecho();
		    if ((pcap_lookupnet(temp,&netp,&maskp,errbuf))==-1)
		      {
			 w_error(0, "          Impossible to use device: %s",temp);
		      }
		    else
		      {
			 ok = 1;
			 strcpy(dev,temp);
		      }
		 }

	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       return(0);
	       break;

	     case 1:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,2,2,"Insert name file for report logging");
	       mvwprintw(pop_up,3,2,"(NULL takes no effects):");
	       wmove(pop_up,5,2);
	       echo();
	       wgetnstr(pop_up, reportl, 50);
	       noecho();
	       if (strcmp (reportl, "NULL")) /* != NULL */
		 {
		    (lr=1);
		    logname=reportl;
		 }
	       else
		 {
		    (lr=0);
		    strcpy(reportl,"NULL");
		 }
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       return(0);
	       break;

	     case 2:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       if(check_pthread() == 1)
		 return(0);
	       pop_up_win();
	       /*mvwprintw(pop_up,2,2,"Do you want to demonize process (y/n)?");
	       wmove(pop_up,4,2);
	       do
		 {
		    ris=wgetch(pop_up);
		    if (ris == 'y')
		      demonize=1;

		    else if (ris == 'n')
		      demonize=0;

		 }
	       while( ris != 'y' && ris != 'n');*/
	       mvwprintw(pop_up,6,18, "Not yet implemented!");
	       mvwprintw(pop_up,12,19,"Press 'q' to quit");
	       do
		 {
		    ris=wgetch(pop_up);

		 }
	       while( ris != 'q');
	       wrefresh(pop_up);
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       return(0);
	       break;

	     case 3:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       shutdown_thread();
	       return(0);
	       break;

	     case 4:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,5,9, "NAST - Network Analyzer Sniffer Tool");
	       mvwprintw(pop_up,7,11, "Version %s (C) Embyte & Snifth", PACKAGE_VERSION);
	       mvwprintw(pop_up,9,18,"Press 'q' to quit");
	       do
		 {
		    ris=wgetch(pop_up);

		 }
	       while( ris != 'q');
	       wrefresh(pop_up);
	       return(0);
	       break;

	     case 5:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       help_win();
	       attron(A_BOLD);
	       mvwprintw(help,2,2,"[F1]          -> Menu Selection");
	       mvwprintw(help,3,2,"[F2]          -> Main window interactions");
	       mvwprintw(help,4,2,"[F3]          -> Info window interactions");
	       mvwprintw(help,5,2,"[UP]          -> Scrolling UP windows (1 line)");
	       mvwprintw(help,6,2,"[DOWN]        -> Scrolling DOWN windows (1 line)");
	       mvwprintw(help,7,2,"[PgUP]        -> Scrolling UP windows (5 lines)");
	       mvwprintw(help,8,2,"[PgDOWN]      -> Scrolling DOWN windows (5 lines)");
	       mvwprintw(help,9,2,"[Shift + s]   -> Sniffer Menu");
	       mvwprintw(help,10,2,"[Shift + a]   -> Analyzer Menu");
	       mvwprintw(help,11,2,"[Shift + o]   -> Options Menu");
	       mvwprintw(help,12,2,"[i]           -> Show informations about options");
	       mvwprintw(help,13,2,"[x]           -> Erase Main Window");
	       mvwprintw(help,14,2,"[d]           -> Erase Info window");
	       mvwprintw(help,15,2,"[h]           -> This help");
	       mvwprintw(help,16,2,"[q]           -> Exit all windows");
	       mvwprintw(help,17,2,"When you use the sniffer pay attention that the");
	       mvwprintw(help,18,2,"options MUST be selected BEFORE sniffer starting!");
	       mvwprintw(help,20,2,"[Shift + q]   -> Exit NAST");
	       attroff(A_BOLD);
	       do
		 {
		    ris=wgetch(help);

		 }
	       while( ris != 'q');
	       wrefresh(help);
	       werase(help);
	       nmenu();
	       redrawscrollwin(princ,0);
	       redrawscrollwin(winfo,0);
	       return(0);
	       break;

	     case 6:
	       unpost_menu(my_menu);
	       free_menu(my_menu);
	       for(i = 0; i < n_choices; ++i)
		 free_item(my_items[i]);
	       werase(my_menu_win);
	       wrefresh(my_menu_win);
	       box(my_nmenu_win, 0, 0);
	       wrefresh(my_nmenu_win);
	       redrawscrollwin(princ,0);
	       refresh();
	       pop_up_win();
	       mvwprintw(pop_up,7,10,"Are you sure you want to exit (y/n)?");
	       wmove(pop_up,4,2);
	       do
		 {
		    ris=wgetch(pop_up);
		    if (ris == 'y')
		      {
			 init_scr();
			 shutdown_thread();
			 endwin();
			 exit(0);
		      }

		    else if (ris == 'n');
		 }
	       while( ris != 'y' && ris != 'n');
	       delwin(pop_up);
	       redrawscrollwin(princ,0);
	       return(0);
	       break;
	    }
	  break;

       }

	wrefresh(my_menu_win);

     }

	/* Unpost and free all the memory taken up */
   unpost_menu(my_menu);
   free_menu(my_menu);
   for(i = 0; i < n_choices; ++i)
     free_item(my_items[i]);
   werase(my_menu_win);
   wrefresh(my_menu_win);
   return (0);
}

void *n_sniff(void *threadid)
{
   init_scr();
   line_s = row_s = 0;
   run_sniffer (promisc, ascii, hex, f, l, tl, tr, n_filter, dev, ldfile);
   pthread_exit(NULL);
}

void *conn_db(void *threadarg)
{
   char device[30];
   u_long ip_src;
   u_long ip_dst;
   u_short sport;
   u_short dport;

   struct thread_conn *th_conn;

   th_conn = (struct thread_conn *) threadarg;

   ip_src  = th_conn->ip_src;
   ip_dst  = th_conn->ip_dst;
   sport   = th_conn->sport;
   dport   = th_conn->dport;

   strcpy(device,th_conn->device);

   connection(device,ip_src,ip_dst,sport,dport);
   pthread_exit(NULL);
}

void *conn_db_r(void *threadarg)
{
   char device[30];
   u_long ip_src;
   u_long ip_dst;
   u_short sport;
   u_short dport;

   struct thread_conn_rst *th_conn;

   th_conn = (struct thread_conn_rst *) threadarg;

   ip_src  = th_conn->ip_src;
   ip_dst  = th_conn->ip_dst;
   sport   = th_conn->sport;
   dport   = th_conn->dport;

   strcpy(device,th_conn->device);

   rst_connection_db(device,ip_src,ip_dst,sport,dport);
   pthread_exit(NULL);
}

void *t_arp(void *threadarg)
{
   char device[30];
   int lg;

   struct thread_arp *arp;

   arp=(struct thread_arp *) threadarg;

   lg = arp->lr;
   strcpy(device,arp->device);
   car(device,lg);
   pthread_exit(NULL);

};

int s_select()
{
   int i, l, c, x;

   char currfil[200];

   i = x = 0;
   l=1;

   while((c = getch()) != 'q')
     {
	switch(c)
	  {
	   case KEY_DOWN:
	     memset(&currfil, 0, sizeof(currfil));

	     if(l>=(nmax-1))
	       break;

	     else
	       {

		  wmove(winfo->win, l, 2);
		  wattron(winfo->win, COLOR_PAIR(4));
		  waddstr(winfo->win, sf[i].string);
		  wattroff(winfo->win, COLOR_PAIR(4));
		  strcpy(currfil,sf[i].sfilter);
	       }
	     if(l>4)
	       {
		  winscroll(winfo,+1);
		  SAFE_SCROLL_REFRESH(winfo);
	       }

	     if(l==1)
	       ;
	     else
	       {
		  wmove(winfo->win, --l, 2);
		  wattron(winfo->win, A_NORMAL);
		  waddstr(winfo->win, sf[--i].string);
		  wattroff(winfo->win, A_NORMAL);
		  ++l;
		  ++i;
	       }
	     redrawscrollwin(winfo, 0);
	     strcpy(currfil,sf[i].sfilter);
	     ++l;
	     ++i;

	     break;

	   case KEY_UP:
	     memset(&currfil, 0, sizeof(currfil));

	     if (l<=2) break;

	     winscroll(winfo,-1);
	     SAFE_SCROLL_REFRESH(winfo);

	     --l;
	     --i;

	     if(l==1)
	       ;
	     else
	       {
		  wmove(winfo->win, --l, 2);
		  wattron(winfo->win, COLOR_PAIR(4));
		  waddstr(winfo->win, sf[--i].string);
		  wattroff(winfo->win, COLOR_PAIR(4));
		  strcpy(currfil,sf[i].sfilter);
		  ++l;
		  ++i;

		  wmove(winfo->win, l, 2);
		  wattron(winfo->win, A_NORMAL);
		  waddstr(winfo->win, sf[i].string);
		  wattroff(winfo->win, A_NORMAL);

		  redrawscrollwin(winfo, 0);

	       }
	     break;

	   case 10:
	     if(currfil==0)
	       break;
	     if(x)
	       {
		  pthread_cancel(thID[5]);
		  pthread_join(thID[5],NULL);
	       }
	     x=1;
	     streamg (dev,currfil);

	     break;
	  }

     }
   return 0;
}

int r_select()
{
   int i, n, c, l;
   char currfil[200];
   u_long seq;
   u_long ack;
   u_long s_ip;
   u_long d_ip;
   u_short s_port,d_port;

   seq = ack = s_ip = d_ip = s_port = d_port = i = n = 0;
   l = 1;

   while((c = getch()) != 'q')
     {
	switch(c)
	  {
	   case KEY_DOWN:
	     memset(&currfil, 0, sizeof(currfil));
	     ack=0;
	     seq=0;

	     if(l>=(nmax-1))
	       break;

	     else
	       {

		  wmove(winfo->win, l, 2);
		  wattron(winfo->win, COLOR_PAIR(4));
		  waddstr(winfo->win, sf[i].string);
		  wattroff(winfo->win, COLOR_PAIR(4));
		  strcpy(currfil,sf[i].sfilter);
		  seq=sf[i].seq;
		  ack=sf[i].ack;
		  s_ip=sf[i].ip_src;
		  d_ip=sf[i].ip_dst;
		  s_port=sf[i].s_port;
		  d_port=sf[i].d_port;
	       }
	     if(l>4)
	       {
		  winscroll(winfo,+1);
		  SAFE_SCROLL_REFRESH(winfo);
	       }

	     if(l==1)
	       ;
	     else
	       {
		  wmove(winfo->win, --l, 2);
		  wattron(winfo->win, A_NORMAL);
		  waddstr(winfo->win, sf[--i].string);
		  wattroff(winfo->win, A_NORMAL);
		  ++l;
		  ++i;
	       }
	     redrawscrollwin(winfo, 0);
	     strcpy(currfil,sf[i].sfilter);
	     seq=sf[i].seq;
	     ack=sf[i].ack;
	     s_ip=sf[i].ip_src;
	     d_ip=sf[i].ip_dst;
	     s_port=sf[i].s_port;
	     d_port=sf[i].d_port;
	     ++l;
	     ++i;

	     break;

	   case KEY_UP:
	     memset(&currfil, 0, sizeof(currfil));
	     seq=0;
	     ack=0;

	     if (l<=2) break;

	     winscroll(winfo,-1);
	     SAFE_SCROLL_REFRESH(winfo);

	     --l;
	     --i;

	     if(l==1)
	       ;
	     else
	       {
		  wmove(winfo->win, --l, 2);
		  wattron(winfo->win, COLOR_PAIR(4));
		  waddstr(winfo->win, sf[--i].string);
		  wattroff(winfo->win, COLOR_PAIR(4));
		  strcpy(currfil,sf[i].sfilter);
		  seq=sf[i].seq;
		  ack=sf[i].ack;
		  s_ip=sf[i].ip_src;
		  d_ip=sf[i].ip_dst;
		  s_port=sf[i].s_port;
		  d_port=sf[i].d_port;
		  ++l;
		  ++i;

		  wmove(winfo->win, l, 2);
		  wattron(winfo->win, A_NORMAL);
		  waddstr(winfo->win, sf[i].string);
		  wattroff(winfo->win, A_NORMAL);

		  redrawscrollwin(winfo, 0);

	       }
	     break;

	   case 10:
	     if(currfil==0)
	       break;

	     for(n=0;n<3;n++)
	       reset_conn(dev,s_ip,d_ip,s_port,d_port,seq,ack);
	     break;
	  }

     }
   return 0;
}

#endif

