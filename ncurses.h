#include <stdio.h>
#include <string.h>
#include <ncurses.h>

WINDOW *create_newwin(int height, int width, int starty, int startx);
void init_ncurses();
void end_ncurses();
void n_draw_border();
void print_ncurses(int line_num,char * txt);
void print_headers();
void print_status(int y,int type,int chan,int pkt_cnt,int error_cnt);
void print_running_status(bool running);

