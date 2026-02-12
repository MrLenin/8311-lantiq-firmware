/******************************************************************************

                               Copyright (c) 2011
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

/**
 *
 * v0.0.1 2010.06.18
 * - Initial release
 *
 * v0.0.2 2011.09.23
 * - WHAT string added
 *
 */
#ifdef HAVE_CONFIG_H
#include "drv_optic_config.h"
#endif

#ifdef LINUX

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include <signal.h>
#include <getopt.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include "optic_top.h"
#include "tui.h"
#include "dump.h"

const char optic_top_whatversion[] = OPTIC_TOP_WHAT_STR;

/** info group description */
struct info_descript {
	/** ASCII symbol which uniquely identifies info group
	    (should be A-Z, a-z, 0-9) */
	int key;
	/** info group name */
	char name[100];
	/** info group table entry get handler */
	tableentry_get *p_tableentry_get;
	/** info group entire table get handler */
	table_get *p_table_get;
	/** Start entry, used for scrolling */
	int start;
	/** Total entries number */
	int total;
};

static struct info_descript info_group[] =
{
	{ 'c', "configuration",                 table_entry_get_config,
						table_get_config,       0, 0 },
	{ 'r', "range settings",                table_entry_get_ranges,
						table_get_ranges,       0, 0 },
	{ 't', "temperature tables",            table_entry_get_temperature,
					        table_get_temperature,  4*77, 0 },
	{ 'T', "temperature translation table", table_entry_get_temptrans,
					        table_get_temptrans,    100/4, 0 },
	{ 'g', "gain settings",                 table_entry_get_gain,
					        table_get_gain,         0, 0 },
	{ 'm', "monitor calibration",           table_entry_get_monitor,
					        table_get_monitor,      0, 0 },
	{ 'f', "fusing registers",              table_entry_get_fuses,
					        table_get_fuses,        0, 0 },
	{ 's', "status",                        table_entry_get_status,
					        table_get_status,       0, 0 },
	{ 'a', "alarms",                        table_entry_get_alarm,
					        table_get_alarm,        0, 0 },
	{ 'v', "version & status",              table_entry_get_version,
					        table_get_version,      0, 0 },
};

/** Device path */
#define OPTIC_DEVICE_PATH "/dev/optic0"

/** Maximum line length for table/dump data */
#define LINE_LEN 255

int fd_dev;

/** Selected info group */
static int sel_group = 0;

/** info update delay (in ms) */
static int update_delay = 1000;

/** Batch mode (1 - yes) */
static int batch_mode = 0;

/** Filter string */
static char filter[LINE_LEN] = { 0 };

/** Buffer for the file data (for data exported via /proc) */
static char shared_buff[1024][LINE_LEN];

/** Counters group minimum value */
#define CG_MIN 0

/** Counters group maximum value */
#define CG_MAX (sizeof(info_group)/sizeof(info_group[0]) - 1)

/** Counters groups number */
#define CG_NUM (CG_MAX - CG_MIN + 1)

/** Selected counters group shortcut */
#define cg info_group[sel_group]

/** Convert char to lower case */
#define CHAR_TO_LOWER(x) ((x & 0xff) + 32)

/** Check if char is in upper case */
#define IS_CHAR_UPPER(x) ((x & 0xff) >= 'A' && (x & 0xff) <= 'Z')

/** Count cursor position in percents */
#define POSITION(pos, total) \
      ((pos == 0 || total == 0) ? 0 : (unsigned int) (pos * 100 / total))

/** Get number of lines occupied by string */
#define LINES_NUM(str) \
      (strlen(str) / getmaxx(stdscr) \
       + ((strlen(str) % getmaxx(stdscr) > 0) ? 1 : 0))

/** Check if line will be filtered (not showed)

   \param[in] pStr Input string

   \return 1 if line will be filtered
*/
static int is_filtered ( const char *str )
{
	if (strlen(str) == 0 || strstr(str, filter)) {
		return 0;
	} else {
		return 1;
	}
}

int file_read ( int file_nr, ... )
{
	FILE *f;
	unsigned int line = 0;
	int i;
	char *p, *filename;
	va_list arg;

	va_start(arg, file_nr);

	if (file_nr <= 0)
		return 0;

	for (i = 0; i < file_nr; i++) {
		filename = va_arg(arg, char *);

		f = fopen(filename, "r");
		if (!f)
			return 0;

		while ((line < sizeof(shared_buff) / sizeof(shared_buff[0])) &&
		       (fgets(shared_buff[line], sizeof(shared_buff[0]), f))) {
			p = strstr(shared_buff[line], "\n");

			if (p)
				*p = 0;
			line++;
		}

		fclose(f);
	}

	return line;
}

char *file_line_get ( int line )
{
	return shared_buff[line];
}

/** Shutdown handler

   \param[in] sig Signal
*/
static void shutdown ( int sig )
{
	curs_set(1);
	endwin();

#ifndef OPTIC_SIMULATION
	close(fd_dev);
#endif

	exit(0);
}

#ifdef SIGWINCH
/** Resize indication */
static volatile sig_atomic_t need_resize = 0;

/** Resize handler

   \param[in] sig Signal
*/
static void resize ( int sig )
{
	need_resize = 1;
	signal(sig, resize);
}
#endif

/** Fetch info (update application's data with device's one)

   \param[in] Counters group to fetch

   \return Number of entries in counters table; -1 if data fetch handler is
           not defined
*/
static int info_fetch ( int group_index )
{
	if (info_group[group_index].p_table_get == NULL) {
		info_group[group_index].total = 0;
		return -1;
	}

	info_group[group_index].total = info_group[group_index].p_table_get();

	if (info_group[group_index].start > info_group[group_index].total)
		info_group[group_index].start = info_group[group_index].total;

	return info_group[group_index].total;
}

/** Write table to file

   \param[in] fOut    File to write in
   \param[in] nCntGrp Counters group to write out
*/
static void table_write ( FILE *out, int group_index)
{
	int i;
	char buff[LINE_LEN];

	if (info_group[group_index].p_tableentry_get == NULL)
		return;

	info_group[group_index].p_tableentry_get(-1, buff);

	fprintf(out, buff);
	fprintf(out, "\n");

	for (i = 0; i < info_group[group_index].total; i++) {
		info_group[group_index].p_tableentry_get(i, buff);

		fprintf(out, buff);
		fprintf(out, "\n");
	}
}

/** Prompt line

   \param[in]     pPrefix Prompt prefix
   \param[in,out] pStr    Return entered string
*/
static void prompt ( const char *prefix, char *str )
{
	int key;
	int len = strlen(str);
	char run = 1;

	curs_set(1);

	while (run) {
		move(getmaxy(stdscr) - 1, 0);
		printw("%s%s", prefix, str);
		clrtoeol();
		refresh();

		key = (int) getch();

		switch (key) {
		case KEY_ENTER:
			run = 0;
			break;
		case KEY_BACKSPACE:
		case KEY_BACKSPACE2:
			if (len)
				str[--len] = 0;
			break;
		default:
			if (key != 0) {
				if (((key >= '!') && (key <= '~')) ||
				    (key == ' ')) {
					str[len] = key;
					len++;
					str[len] = 0;
				}
			}
			break;
		}
	}

	curs_set(0);
}

/** Output information message

   \param[in] pText Text to print
*/
static void notify ( const char *text )
{
	/*attron(A_STANDOUT);*/
	mvaddstr(getmaxy(stdscr) - 1, 0, text);
	/*attroff(A_STANDOUT);*/
	clrtoeol();
	refresh();
	getch();
}

/** Help window handler */
static void helpwindow_handle ( void )
{
	int run = 1;
	unsigned int i;
	int line;
	int help_start = 0;
	int key;
	int c, r;

	static const char *help_predef[] = {
	"\0",
	"  Up, Ctrl-y          Scroll up\0",
	"  Down, Ctrl-e        Scroll down\0",
	"\0",
	"  Pg down, Ctrl-d     Scroll page down\0",
	"  Pg up, Ctrl-u       Scroll page up\0",
	"\0",
	"  Home                Jump to first line\0",
	"  End                 Jump to last line\0",
	"\0",
	"  /                   Define filter\0",
	"\0",
	"  Ctrl-w              Write selected (current page) counters to file\0",
	"                      /tmp/<Date>_<Time>_<Group>.txt\0",
	"  Ctrl-a              Dump all counters to file /tmp/<Date>_<Time>.txt\0",
	"\0",
	"  ?, Ctrl-h           Show this help window\0",
	"  Ctrl-x, Ctrl-c      Exit program\0",
	"\0"
	};

	clear();

	while (run) {
		/* header */
		attron(A_UNDERLINE);
		mvaddstr(0, 0, "Help for optic_top version " PACKAGE_VERSION "\n");
		attroff(A_UNDERLINE);

		/* body */
		for (line=1, i=help_start; i < (sizeof(help_predef) /
		     sizeof(help_predef[0])); i++, line++) {
			if (line > getmaxy(stdscr) - 2)
				continue;

			move(line, 0);
			printw("%s\n", help_predef[i]);
		}

		if (help_start <= (int)(sizeof(help_predef) /
					sizeof(help_predef[0])))
			i = CG_MIN;
		else
			i = CG_MIN + help_start -
			    (sizeof(help_predef) / sizeof(help_predef[0]));

		for (; i <= CG_MAX; i++, line++) {
			if (line > getmaxy(stdscr) - 2)
				continue;

			move(line, 0);
			if (IS_CHAR_UPPER(info_group[i].key)) {
				printw("  %c (Shift-%c)         Show %s\n",
					info_group[i].key,
					CHAR_TO_LOWER(info_group[i].key),
					info_group[i].name);

			} else {
				printw("  %c                   Show %s\n",
					info_group[i].key,
					info_group[i].name);
			}
		}

		/* footer */
		mvaddstr(getmaxy(stdscr) - 1, 0, "Press ENTER to get back...");
		clrtoeol();

		refresh();

		do {
#ifdef SIGWINCH
			if (need_resize) {
				terminalsize_get ( &c, &r );
				resize_term ( r, c );

				need_resize = 0;
				clear();

				help_start = 0;

				break;
			}
#endif
			key = key_read();

			switch (key) {
			case KEY_HOME:
				help_start = 0;
				clear();
				break;
			case KEY_END:
				help_start = (sizeof(help_predef) /
					      sizeof(help_predef[0]))
					      + CG_NUM + 2 - getmaxy(stdscr);

				if (help_start < 0)
					help_start = 0;

				clear();
				break;
			case KEY_CTRL_E:
			case KEY_DOWN:
				if (help_start < (int) ((sizeof(help_predef) /
				    sizeof(help_predef[0])) + CG_NUM - 2)) {
					help_start++;
					clear();
				}
				break;
			case KEY_CTRL_Y:
			case KEY_UP:
				if (help_start) {
					help_start--;
					clear();
				}
				break;
			case KEY_CTRL_D:
			case KEY_NPAGE:
				if (help_start + getmaxy(stdscr) - 2 <
				    (int)((sizeof(help_predef) /
				    sizeof(help_predef[0])) + CG_NUM + 3)) {
					help_start += getmaxy(stdscr) - 3;
					clear();
				}
				break;
			case KEY_CTRL_U:
			case KEY_PPAGE:
				if (help_start - getmaxy(stdscr) - 2 < 0)
					help_start = 0;
				else
					help_start -= getmaxy(stdscr) - 2;

				clear();
				break;
			case KEY_ENTER:
				run = 0;
				break;
			case KEY_CTRL_X:
				shutdown(0);
				break;
			}
		} while (!key);
	}
}

/** Get first line number */
static int first_line_get ( void )
{
	char buff[LINE_LEN];
	int line = 0;

	while (line < cg.total) {
		cg.p_tableentry_get(line, buff);

		if (!is_filtered(buff))
			return line;

		line++;
	}

	return 0;
}

/** Get nth last line

   \param[in] nNth nth line number
*/
static int last_line_get ( int index )
{
	char buff[LINE_LEN];
	int line = cg.total - 1;

	while (line >= 0) {
		cg.p_tableentry_get(line, buff);

		if (!is_filtered ( buff )) {
			if (index > 0)
				index -= LINES_NUM(buff);

			if (index <= 0)
				return line;
		}

		line--;
	}
	return -1;
}

/** Get next line after given

   \param[in] index Start search from this line
*/
static int next_line_get ( int index )
{
	char buff[LINE_LEN];

	while (index < cg.total - 1) {
		index++;
		cg.p_tableentry_get ( index, buff );

		if (!is_filtered ( buff ))
			return index;
	}

	return -1;
}

/** Get next line before given

   \param[in] index Start search from this line
*/
static int prev_line_get ( int index )
{
	char buff[LINE_LEN];

	while (index > 0) {
		index--;
		cg.p_tableentry_get ( index, buff );

		if (!is_filtered ( buff ))
			return index;
	}

	return -1;
}

/** Get next page after given

   \param[in] index Start search from this line
*/
static int next_page_get ( int index )
{
	char buff[LINE_LEN];
	int page_lines = getmaxy(stdscr) - 2;

	while (index < cg.total - 1) {
		index++;
		cg.p_tableentry_get ( index, buff );

		if (!is_filtered ( buff )) {
			page_lines--;

			if (page_lines <= 0) {
				return index;
			}
		}
	}

	return -1;
}

/** Get next page before given

   \param[in] index Start search from this line
*/
static int prev_page_get ( int index )
{
	char buff[LINE_LEN];
	int page_lines = getmaxy(stdscr) - 2;

	while (index > 0) {
		index--;
		cg.p_tableentry_get ( index, buff );

		if (!is_filtered ( buff )) {
			page_lines--;

			if (page_lines <= 0) {
				return index;
			}
		}
	}

	return -1;
}

/** Main window handler */
static void mainwindow_handle ( void )
{
	int key;
	int i;
	char buff[LINE_LEN];
	struct timeval tv, tv_upd_time;
	FILE *f_dump;
	int line;
	int c, r;
	int need_update = 1;

	gettimeofday(&tv_upd_time, 0);

	clear();

	while (1) {
#ifdef SIGWINCH
		if (need_resize) {
			terminalsize_get(&c, &r);
			resize_term(r, c);

			need_resize = 0;
			clear();
		}
#endif

		if ((cg.p_tableentry_get == NULL) || (cg.p_table_get == NULL)) {
			sprintf(buff, "ERROR: Can't retrieve data for %s; "
				"no handler defined", cg.name);
		} else {
			gettimeofday(&tv, 0);

			if (tv.tv_sec == (tv_upd_time.tv_sec +
			                  update_delay / 1000)) {
				if (tv.tv_usec - tv_upd_time.tv_usec >
				    update_delay % 1000 * 1000) {
					tv_upd_time = tv;
					need_update = 1;
				}
			} else {
				if (tv.tv_sec - tv_upd_time.tv_sec >
				    update_delay / 1000) {
					tv_upd_time = tv;
					need_update = 1;
				}
			}
		}

		if (need_update) {
			(void)info_fetch(sel_group);

			cg.p_tableentry_get(-1, buff);

			attron(A_UNDERLINE);
			mvaddstr(0, 0, buff);
			attroff(A_UNDERLINE);

			/* data */
			if (cg.p_tableentry_get != NULL) {
				for (i = cg.start, line = 1; (i < cg.total) &&
				     (line + 1 < getmaxy(stdscr)); i++) {
					cg.p_tableentry_get(i, buff);

					if (!is_filtered ( buff )) {
						move(line, 0);
						addstr(buff);

						line += LINES_NUM(buff);
					}
				}
			}

			/* footer */
			mvaddstr(getmaxy(stdscr)- 1, 0,
				 "Press ? or Ctrl-h for help");

			sprintf(buff, "%s   Delay: %ums  %3u%%%%",
				cg.name, update_delay,
				POSITION(cg.start, cg.total));

			mvaddstr(getmaxy(stdscr) - 1,
				 getmaxx(stdscr) - strlen(buff) - 1, buff);
			clrtoeol();

			refresh();

			need_update = 0;
		}

		key = key_read();
		switch (key) {
		case 0:
			break;
		case '/':
			prompt("/", filter);

			line = prev_line_get(cg.start);
			if (line >= 0) {
				cg.start = line;
			} else {
				cg.start = first_line_get();
			}

			clear();
			break;
		case KEY_HOME:
			line = first_line_get();

			if (cg.start != line) {
				cg.start = first_line_get();
				clear();
			}
			break;
		case KEY_END:
			line = last_line_get(getmaxy(stdscr) - 2);
			if ((line >= 0) && (cg.start != line)) {
				cg.start = line;
				clear();
			}
			break;
		case KEY_CTRL_H:
		case '?':
			helpwindow_handle();
			clear();
			break;
		case KEY_CTRL_X:
			shutdown(0);
			break;
		case KEY_CTRL_E:
		case KEY_DOWN:
			line = next_line_get(cg.start);
			if ((line >= 0) && (cg.start != line)) {
				cg.start = line;
				clear();
			}
			break;
		case KEY_CTRL_Y:
		case KEY_UP:
			line = prev_line_get(cg.start);
			if ((line >= 0) && (cg.start != line)) {
				cg.start = line;
				clear();
			}
			break;
		case KEY_CTRL_D:
		case KEY_NPAGE:
			line = next_page_get(cg.start);
			if ((line >= 0) && (cg.start != line)) {
				cg.start = line;
				clear();
			}
			break;
		case KEY_CTRL_U:
		case KEY_PPAGE:
			line = prev_page_get(cg.start);
			if ((line >= 0) && (cg.start != line)) {
				cg.start = line;
				clear();
			} else
			if ((line < 0) && (cg.start != 0)) {
				cg.start = 0;
				clear();
			}
			break;
		case KEY_CTRL_W:
			gettimeofday(&tv, 0);
			sprintf(buff, "/tmp/%lu_%lu_%s.txt", tv.tv_sec,
				tv.tv_usec, cg.name);

			f_dump = fopen(buff, "w");
			if (f_dump == NULL) {
				clear();

				sprintf(buff, "Can't save to '/tmp/%lu_%lu_%s.txt'. "
					"Press any key to continue...",
					tv.tv_sec, tv.tv_usec, cg.name);
				notify(buff);

				clear();
				break;
			}

			table_write(f_dump,sel_group);
			fclose(f_dump);
			clear();

			sprintf(buff, "Saved to '/tmp/%lu_%lu_%s.txt'. "
				"Press any key to continue...",
				tv.tv_sec, tv.tv_usec, cg.name);
			notify(buff);
			clear();
			break;
		case KEY_CTRL_A:
			gettimeofday(&tv, 0);
			sprintf(buff, "/tmp/%lu_%lu.txt", tv.tv_sec,
				tv.tv_usec);

			clear();
			mvaddstr(getmaxy(stdscr) - 1, 0, "Fetching all data..");
			refresh();

			f_dump = fopen(buff, "w");
			if (f_dump == NULL) {
				clear();

				sprintf(buff, "Can't save to '/tmp/%lu_%lu.txt'"
					" Press any key to continue...",
					tv.tv_sec, tv.tv_usec);
				notify(buff);
				clear();
				break;
			}

			for (i = (int) CG_MIN; i < (int)CG_MAX; i++) {
				if (info_fetch(i) >= 0) {
					table_write(f_dump, i);
					fprintf(f_dump, "\n");
				}
			}

			fclose(f_dump);
			clear();

			sprintf(buff, "Saved to '/tmp/%lu_%lu.txt'. "
				"Press any key to continue...",
				tv.tv_sec, tv.tv_usec);
			notify(buff);
			clear();
			break;
		default:
			for (i = (int) CG_MIN; i <= (int)CG_MAX; i++) {
				if (key == info_group[i].key) {
					sel_group = i;
					(void)info_fetch(sel_group);

					clear();
					break;
				}
			}
			break;
		}

		if (key)
			need_update = 1;
	}
}

/** Print help */
static void help_print ( void )
{
	int i;

	printf("optic_top V" OPTIC_TOP_VERSION " (compiled on "
		__DATE__ " " __TIME__ ")\n");

	printf("Usage: optic_top [options]"
		"\n\n"
		"Options:\n"
		"\t-b, --batch       Start in `Batch mode` \n"
		"\t-d, --delay <ms>  Counters update delay\n"
		"\t-g, --group <grp> Show specified counters upon startup \n");

	printf("\t                  "
		"Possible group values(use either symbol or full name):\n");
	for (i = (int) CG_MIN; i <= (int) CG_MAX; i++) {
		printf("\t                     %c - %s\n", info_group[i].key,
			info_group[i].name);
	}

	printf("\n"
		"\t-h, --help        Print help (this message)\n"
		"\t-v, --version     Print version information\n");
}

/** Parse command line arguments

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
static int parse_arguments ( int argc, char *argv[])
{
	int i;
	int c;
	int opt_index;

	static struct option opt_str[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ "batch", no_argument, 0, 'b' },
		{ "delay", required_argument, 0, 'd' },
		{ "group", required_argument, 0, 'g' },
		{ NULL, no_argument, 0, 'd' }
	};

	static const char long_opts[] = "hvbd:g:";

	do {
		c = getopt_long(argc, argv, long_opts, opt_str, &opt_index);

		if (c == -1)
			return 0;

		switch (c) {
		case 'h':
			help_print();
			return 1;
		case 'v':
			printf("optic_top V" OPTIC_TOP_VERSION " (compiled on "
				__DATE__ " " __TIME__ ")\n");
			return 1;
		case 'b':
			batch_mode = 1;
			break;
		case 'd':
			update_delay = atoi(optarg);

			if (update_delay == 0) {
				fprintf(stderr,
					"Invalid value for option 'd'\n");
				return 1;
   			}
			break;
		case 'g':
			sel_group = -1;
			for (i = (int) CG_MIN; i <= (int) CG_MAX; i++) {
				if (strlen(optarg) == 1) {
					if (info_group[i].key == optarg[0]) {
						sel_group = i;
						break;
					}
				} else {
					if (strcmp(info_group[i].name, optarg)
					    == 0) {
 						sel_group = i;
 						break;
					}
				}
			}

 			if (sel_group == -1) {
				fprintf(stderr, "Invalid value for option 'g'\n");
				return 1;
			}
			break;
		default:
			return 1;
		}
	} while (1);

	return 0;
}

/** Entry point

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
int main ( int argc, char *argv[] )
{
	if (parse_arguments(argc, argv))
		return 0;

#ifndef OPTIC_SIMULATION
	fd_dev = open(OPTIC_DEVICE_PATH, O_RDWR, 0644);

	if (fd_dev < 0) {
		fprintf(stderr, "Can't open device " OPTIC_DEVICE_PATH "\n");
		return 1;
	}
#endif

	(void)info_fetch(sel_group);

	if (batch_mode == 1) {
		table_write(stdout, sel_group);

#ifndef OPTIC_SIMULATION
	close(fd_dev);
#endif
	} else {
		signal(SIGINT, shutdown);

		initscr();

		keypad(stdscr, TRUE);
		nonl();
		cbreak();
		noecho();
		curs_set(0);

#ifdef SIGWINCH
		signal(SIGWINCH, resize);
#endif
		mainwindow_handle();

		shutdown(0);
	}

	return 0;
}

#endif
