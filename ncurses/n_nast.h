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

#include "../include/nast.h"

#ifdef HAVE_LIBNCURSES		/*don't compile if we haven't ncurses*/

# include <menu.h>

# define SAFE_WREFRESH(x)   do { wrefresh(x); } while(0)

# define SAFE_WIN_REFRESH(x)   do { wrefresh(x->win); } while(0)
# define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

# define SAFE_SCROLL_REFRESH(sx) do {  \
   pnoutrefresh(sx->win, sx->y_scroll, 0, sx->y + 1, sx->x + 1, sx->y + sx->lines - 2, sx->cols - 1 ); \
   wnoutrefresh(sx->out);              \
   doupdate();                         \
} while(0)

# define POLL_WGETCH(x, y)   do {    \
   struct pollfd poll_fd = {        \
      .fd = 0,                      \
      .events = POLLIN,             \
   };                               \
   poll(&poll_fd, 1, 1);            \
   if (poll_fd.revents & POLLIN)    \
      x = wgetch(y);                \
   else                             \
      usleep(1000);                 \
} while(0)

struct scrolling_window
{
   WINDOW *win;
   WINDOW *out;
   int y_scroll;
   int y_max;
   int lines;
   int cols;
   int x;
   int y;
   char *title;
};
typedef struct scrolling_window N_SCROLLWIN;

N_SCROLLWIN *newscrollwin(int lines, int cols, int y, int x, char *title, int maxlines);
void redrawscrollwin(N_SCROLLWIN *win, int focus);
void drawscroller(N_SCROLLWIN *win);
void winscroll(N_SCROLLWIN *win, int delta);
void delscrollwin(N_SCROLLWIN **win);

void nmenu(void);
int sniffer_menu(void);
int analyzer_menu(void);
int options_menu(void);
void pop_up_win(void);
void *conn_db(void *threadarg);
void *conn_db_r(void *threadarg);
int connection(char *dev,u_long ip_src,u_long ip_dst,u_short sport,u_short dport);
int rst_connection_db(char *dev,u_long ip_src,u_long ip_dst,u_short sport,u_short dport);
int reset_conn(char *dev,u_long s_ip, u_long d_ip, u_short s_port, u_short d_port,u_long seq, u_long ack);
int streamg (char *dev,char *sfilter);
void data_sniffo_stream (char *data_info, u_int len);
void init_scr(void);
int reset(char *dev, char *sfilter);
int check_pthread(void);
int shutdown_thread(void);
void help_win(void);

WINDOW *query;
WINDOW *werror;
WINDOW *help;
N_SCROLLWIN *princ;
N_SCROLLWIN *winfo;
N_SCROLLWIN *wstream;
N_SCROLLWIN *wconn;

MENU *my_nmenu;
ITEM *curr_item;
WINDOW *my_nmenu_win;
WINDOW *pop_up;

u_short mvar;
u_short promisc,hex,ascii,ld,f,lr,l;
u_short flg;
int linm;
int fileds;
char dev[10];
char n_filter[60];
char ldfile[50];
char tcpdfile[50];
char reportl[50];
char logfile[50];
/*descriptor for stream*/
pcap_t* str;
pcap_dumper_t *dumper;

/* thread for database connections */
pthread_t thID[6];

struct thread_conn
{
   char device[30];
   u_long ip_src;
   u_long ip_dst;
   u_short sport;
   u_short dport;
   int thread_id;
};

struct thread_arp
{
   char device[30];
   int lr;
};

struct thread_conn_rst
{
   char device[30];
   u_long ip_src;
   u_long ip_dst;
   u_short sport;
   u_short dport;
   int thread_id;
};

struct thread_conn th_data[1];
struct thread_conn_rst th_r_data[1];
struct thread_arp th_arp_data[1];

struct connections
{
   unsigned long s_ip;
   unsigned long d_ip;
   unsigned short s_port;
   unsigned short d_port;
   u_long seq;
   u_long ack;
   int lin;
   int pr;
   int set;

}
c_inf[30];

/* connection struct */
struct cnn
{
   char string[200];
   /*filter for tcp stream*/
   char sfilter[200];
   u_long seq;
   u_long ack;
   u_long ip_src;
   u_long ip_dst;
   u_short s_port;
   u_short d_port;
   int cont;
}
sf[30];

/* num max of db connections */
int nmax;

#endif

