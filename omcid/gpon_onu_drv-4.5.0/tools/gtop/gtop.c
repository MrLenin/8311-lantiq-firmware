/******************************************************************************

                               Copyright (c) 2010
                            Lantiq Deutschland GmbH

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <signal.h>
#include <getopt.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#ifndef ONU_SIMULATION
#include <libgen.h>
#endif

#ifndef HAVE_CONFIG_H
static inline char *basename(char *s)
{
	return s;
}
#endif

#include "gtop.h"
#include "tui.h"

#include "common.h"
#include "gtc_counter.h"
#include "gpe_counter.h"
#include "sce_counter.h"
#include "dump.h"

#ifdef INCLUDE_REMOTE_ONU
#include "dti_rpc.h"

char g_remote[MAX_PATH];
#endif

const char gtop_whatversion[] = GTOP_WHAT_STR;

/** Counters group description */
struct cnt_group_desc {
	/** ASCII symbol which uniquely identifies counters group
	  (should be A-Z, a-z, 0-9) */
	int group_key;

	/** ASCII symbol which uniquely identifies counters table
	  (should be A-Z, a-z, 0-9) */
	int key;

	/** Counters group name */
	char name[32];

	/** Counters group table entry get handler */
	table_entry_get_t *table_entry_get;
	/** Counters group entire table get handler */
	table_get_t *table_get;
	/** Enter counters handler */
	table_enter_t *table_enter;
	/** Leave counters handler */
	table_leave_t *table_leave;

	/** Start entry, used for scrolling */
	int start;
	/** Total entries number */
	int total;

	/* path to the profs file to be used */
	const char* input_file_name;
};

/** Counters group initialization handler */
typedef void (group_init_t) (bool init);

/** Proc counters */
#ifdef INCLUDE_PROCFS_SUPPORT
#define CNT_PROC(key1, key2, name, proc_entry) \
{ key1, key2, name, dump_entry_get, dump_get, NULL, NULL, 0, 0, proc_entry },
#else
#define CNT_PROC(key1, key2, name, proc_entry)
#endif

/** Regular counters */
#define CNT(key1, key2, name, entry_get, table_get, on_enter, on_leave) \
{ key1, key2, name, entry_get, table_get, on_enter, on_leave, 0, 0, NULL },

static int help_get(const int fd, const char *dummy);

static group_init_t *group_init_handlers[] = {
	gtc_group_init,
	gpe_group_init,
};

static struct cnt_group_desc cnt_group_desc[] = {
	CNT(0, '?', "Help", dump_entry_get, help_get, NULL, NULL)
	CNT(0, 'a', "Status", status_table_entry_get, status_table_get, NULL, NULL)
	CNT(0, 'b', "Configuration", cfg_table_entry_get, cfg_table_get, NULL, NULL)
	CNT_PROC('c', 'a', "GPE status", "gpe_status")
	CNT_PROC('c', 'b', "GPE exception", "gpe_exp")
	CNT_PROC('c', 'd', "GPE long forward hash", "gpe_longfwdhash")
	CNT_PROC('c', 'e', "GPE long forward ipv6 MC", "gpe_longfwipv6mc")
	CNT_PROC('c', 'f', "GPE long forward ipv6", "gpe_longfwipv6")
	CNT_PROC('c', 'g', "GPE DS GEM port", "gpe_dsgem")
	CNT_PROC('c', 'h', "GPE US GEM port", "gpe_usgem")
	CNT_PROC('c', 'i', "GPE DS MC IPV4", "gpe_dsmcipv4")
	CNT_PROC('c', 'j', "GPE DS MC IPV6", "gpe_dsmcipv6")
	CNT_PROC('c', 'k', "GPE tagging filter", "gpe_tagg")
	CNT_PROC('c', 'l', "GPE NAPT", "gpe_napt")
	CNT_PROC('c', 'm', "GPE NAPT hash", "gpe_napthash")
	CNT_PROC('c', 'n', "GPE FID assignment", "gpe_fidass")
	CNT_PROC('c', 'o', "GPE FID hash", "gpe_fidhash")
	CNT_PROC('c', 'p', "GPE learning limitation", "gpe_learnlim")
	CNT_PROC('c', 'q', "GPE short forward hash", "gpe_shortfwdhash")
	CNT_PROC('c', 'r', "GPE short forward ipv4", "gpe_table_shortfwdipv4")
	CNT_PROC('c', 's', "GPE short forward ipv4 mc", "gpe_shortfwdipv4mc")
	CNT_PROC('c', 't', "GPE short forward MAC", "gpe_shortfwdmac")
	CNT_PROC('c', 'u', "GPE short forward MAC mc", "gpe_shortfwdmacmc")
	CNT_PROC('c', 'v', "GPE VLAN", "gpe_vlan")
	CNT_PROC('c', 'w', "GPE extended VLAN", "gpe_extvlan")
	CNT_PROC('c', 'x', "GPE VLAN rule", "gpe_vlanrule")
	CNT_PROC('c', 'y', "GPE VLAN treatment", "gpe_vlantreatment")
	CNT_PROC('c', 'z', "GPE cop dump", "gpe_table")
	CNT(0, 'd', "GPE info", gpe_table_entry_get, gpe_table_get, NULL, NULL)
	CNT(0, 'e', "GEM port", gem_port_entry_get, gpem_port_table_get, NULL, NULL)
	CNT(0, 'f', "Alloc ID", alloc_id_entry_get, alloc_id_table_get, NULL, NULL)
	CNT_PROC(0, 'g', "TMU dump", "tmu")
	CNT_PROC(0, 'h', "TMU EQT dump", "tmu_eqt")
	CNT_PROC(0, 'i', "TMU EPT dump", "tmu_ept")
	CNT_PROC(0, 'j', "TMU SBIT dump", "tmu_sbit")
	CNT_PROC(0, 'k', "TMU SBOT dump", "tmu_sbot")
	CNT_PROC(0, 'l', "TMU TBST dump", "tmu_tbst")
	CNT_PROC(0, 'm', "TMU PPT dump", "tmu_ppt")
	CNT_PROC(0, 'o', "MERGE dump", "merge")
	CNT_PROC('p', 'a', "GPE constants", "gpe_const")
	CNT_PROC('p', 'b', "GPE bridge port", "gpe_bridgeport")
	CNT_PROC('p', 'c', "GPE PMapper", "gpe_pmapper")
	CNT_PROC('p', 'd', "GPE LAN port", "gpe_lanport")
	CNT_PROC('p', 'e', "GPE policer", "gpe_policer")
	CNT_PROC('p', 'f', "GPE PCP decoding", "gpe_pcpdec")
	CNT_PROC('p', 'g', "GPE DSCP decoding", "gpe_dscpdec")
	CNT_PROC('p', 'h', "GPE PCP encoding", "gpe_pcpenc")
	CNT_PROC('p', 'i', "GPE DSCP encoding", "gpe_dscpenc")
	CNT_PROC('p', 'j', "GPE redirection", "gpe_redir")
	CNT_PROC('p', 'k', "GPE activity", "gpe_act")
	CNT_PROC('p', 'l', "GPE ACL filter", "gpe_aclfilt")
	CNT_PROC('p', 'm', "GPE bridge", "gpe_bridge")
	CNT_PROC('p', 'o', "GPE MAC filter", "gpe_macfilter")
	CNT_PROC('p', 'p', "GPE Counter", "gpe_copcounter")
	CNT_PROC('p', 't', "GPE Enqueue", "gpe_enqueue")
	CNT_PROC(0, 'q', "FSQM LLT dump", "fsqm_llt")
	CNT_PROC(0, 'r', "FSQM RCNT dump", "fsqm_rcnt")
	CNT(0, 's', "Bridge port counter", bridge_port_counter_entry_get, bridge_port_counter_table_get, NULL, NULL)
	CNT_PROC('t', '1', "OCTRLG table dump", "octrlg_table")
	CNT_PROC('t', '3', "ICTRLG table dump", "ictrlg_table")
	CNT('t', 's', "FW status", fw_status_entry_get, fw_status_table_get, NULL, NULL)
	CNT('t', 'd', "FW detailed status", fw_detailed_status_entry_get, fw_detailed_status_table_get, NULL, NULL)
	CNT('t', 'a', "GTC alarms", gtc_alarms_table_entry_get, gtc_alarms_table_get, NULL, NULL)
	CNT('t', 'c', "GTC counters", gtc_counters_table_entry_get, gtc_counters_table_get, NULL, NULL)
	CNT('t', 'b', "BWM trace", gtc_bwmtrace_table_entry_get, gtc_bwmtrace_table_get, NULL, NULL)
	CNT('t', 'e', "Meter", meter_entry_get, meter_table_get, NULL, NULL)
	CNT(0, 'u', "Upstream flow", us_flow_entry_get, us_flow_table_get, NULL, NULL)
	CNT_PROC(0, 'v', "Version", "version")
	CNT(0, 'w', "GPE capability", gpe_capability_entry_get, gpe_capability_table_get, NULL, NULL)
	CNT(0, 'x', "FW perfmeter", fw_perfmeter_entry_get, fw_perfmeter_table_get, fw_perfmeter_on_enter, fw_perfmeter_on_leave)
	CNT_PROC(0, '1', "OCTRLG dump", "octrlg")
	CNT_PROC(0, '2', "OCTRLL dump", "octrll")
	CNT_PROC(0, '3', "ICTRLG dump", "ictrlg")
	CNT_PROC(0, '4', "ICTRLL dump", "ictrll")
	CNT_PROC(0, '5', "FSQM dump", "fsqm")
	CNT_PROC(0, '6', "IQM dump", "iqm")
	CNT_PROC(0, '7', "EIM dump", "eim")
	CNT_PROC(0, '8', "GTC dump", "gtc")
	CNT_PROC(0, '9', "SSB dump", "ssb")
	CNT_PROC(0, '0', "GPE arbiter dump", "gpearb")
};

/** Device path */
#define ONU_DEVICE_PATH "/dev/onu0"

struct gpe_capability g_capability;

int g_dev_fd;

/** Selected counters group */
static unsigned int g_sel_cnt_grp = 0xFFFFFFFF;

/** Counters update delay (in ms) */
static unsigned int g_upd_delay = 1000;

/** Batch mode (1 - yes) */
static int g_batch_mode = 0;

/** Filter string */
static char g_filter[LINE_LEN] = { 0 };

/** Buffer for the file data (for data exported via /proc) */
char g_shared_buff[LINE_MAX][LINE_LEN];

/** Counters group minimum value */
#define CG_MIN 0

/** Counters group maximum value */
#define CG_MAX (ARRAY_SIZE(cnt_group_desc))

/** Selected counters group shortcut */
#define CG cnt_group_desc[g_sel_cnt_grp]

/** Initialize groups

   \param init Where init or shutdown groups
*/
void group_init(bool init)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(group_init_handlers); i++)
		group_init_handlers[i](init);
}

/** Get number of lines occupied by string */
static inline unsigned int lines_num(char *s)
{
	unsigned int max = getmaxx(stdscr);
	unsigned int len = strlen(s);

	if (!len)
		return 1;

	return (len + max - 1) / max;
}

static inline void help_entry_render(char *buff, int group1, int group2)
{
	char shortcut1[4] = "";
	char shortcut2[4] = "";

	if (cnt_group_desc[group1].group_key) {
		shortcut1[0] = cnt_group_desc[group1].group_key;
		shortcut1[1] = '-';
		shortcut1[2] = cnt_group_desc[group1].key;
		shortcut1[3] = '\0';
	} else {
		shortcut1[0] = cnt_group_desc[group1].key;
		shortcut1[1] = '\0';
	}

	if (group2 >= 0) {
		if (cnt_group_desc[group2].group_key) {
			shortcut2[0] = cnt_group_desc[group2].group_key;
			shortcut2[1] = '-';
			shortcut2[2] = cnt_group_desc[group2].key;
			shortcut2[3] = '\0';
		} else {
			shortcut2[0] = cnt_group_desc[group2].key;
			shortcut2[1] = '\0';
		}

		sprintf(buff,
			" %-3s             %-30s"
			"%-3s             %s",
			shortcut1,
			cnt_group_desc[group1].name,
			shortcut2,
			cnt_group_desc[group2].name);
	} else {
		sprintf(buff,
			" %-3s             %s",
			shortcut1,
			cnt_group_desc[group1].name);
	}
}

static int help_get(const int fd, const char *dummy)
{
	unsigned int i;

	static const char *help_predef[] = {
		" ",
		" Up, Ctrl-y      Scroll up                     "
		"Pg up, Ctrl-u   Scroll page up",
		" Down, Ctrl-e    Scroll down                   "
		"Pg down, Ctrl-d Scroll page down",
		" Home            Jump to first line            "
		"End             Jump to last line",
		" /               Define filter                 "
		"Enter           Drop group key",
		" ",
		" Ctrl-w          Write selected (current page) "
		"counters to file /tmp/<Date>_<Time>_<Group>.txt",
		" Ctrl-a          Dump all pages to file "
		"/tmp/<Date>_<Time>.txt",
		"",
		" Ctrl-x, Ctrl-c  Exit program",
		""
	};

	for (i = 0; i < ARRAY_SIZE(help_predef); i++)
		strcpy(g_shared_buff[i], help_predef[i]);

	for (i = 0; i < ARRAY_SIZE(cnt_group_desc); i += 2)
		if (i + 1 < ARRAY_SIZE(cnt_group_desc))
			help_entry_render(g_shared_buff[ARRAY_SIZE(help_predef)
					  + i / 2], i, i + 1);
		else
			help_entry_render(g_shared_buff[ARRAY_SIZE(help_predef)
					  + i / 2], i, -1);

	return ARRAY_SIZE(help_predef)
		+ ARRAY_SIZE(cnt_group_desc) / 2
		+ ARRAY_SIZE(cnt_group_desc) % 2;
}

/** Check if line will be filtered (not showed)

   \param[in] str Input string

   \return 1 if line will be filtered
*/
static int is_filtered(const char *str)
{
	if (strlen(g_filter) == 0)
		return 0;

	/*
	if (strlen(str) == 0)
		return 0;
	*/

	if (strstr(str, g_filter) != NULL)
		return 0;

	return 1;
}

int file_read(const char *name)
{
	FILE *f;
	int line = 0;
	char *p;

	f = fopen(name, "r");
	if (!f)
		return -1;

	while (fgets(g_shared_buff[line], LINE_LEN, f)) {
		p = strchr(g_shared_buff[line], '\n');

		if (p)
			*p = 0;

		line++;

		if (line >= LINE_MAX) {
			fclose(f);
			sprintf(g_shared_buff[0],
				"Number of lines in file '%s' "
				"exceeds max (%d)\n", name, LINE_MAX);
			return 1;
		}
	}

	fclose(f);

	return line;
}

char *file_line_get(int line)
{
	return g_shared_buff[line];
}

/** shutdown handler

   \param[in] sig Signal
*/
static void shutdown(int sig)
{
	curs_set(1);
	endwin();
	/* make sure the cursor for prompt is below last outputs */
	printf("\n\n");

	group_init(false);

#ifndef ONU_SIMULATION
	close(g_dev_fd);
#endif

	if (sig == SIGSEGV)
		fprintf(stderr, "Segmentation fault\n");

	exit(0);
}

#ifdef SIGWINCH
/** resize indication */
static volatile sig_atomic_t g_need_resize = 0;

/** resize handler

   \param[in] sig Signal
*/
static void resize(int sig)
{
	g_need_resize = 1;

	signal(sig, resize);
}
#endif

/** Fetch counters (update application's data with device's one)

   \param[in] Counters group to fetch

   \return Number of entries in counters table; -1 if data fetch handler is
           not defined
*/
static int counters_fetch(const int fd, unsigned int cnt_grp_idx)
{
	if (!cnt_group_desc[cnt_grp_idx].table_get) {
		cnt_group_desc[cnt_grp_idx].total = 0;
		return -1;
	}

	cnt_group_desc[cnt_grp_idx].total =
		cnt_group_desc[cnt_grp_idx].table_get(fd, cnt_group_desc
						      [cnt_grp_idx].
						      input_file_name);

	if (cnt_group_desc[cnt_grp_idx].start
	    > cnt_group_desc[cnt_grp_idx].total)
		cnt_group_desc[cnt_grp_idx].start =
			cnt_group_desc[cnt_grp_idx].total;

	return cnt_group_desc[cnt_grp_idx].total;
}

/** Write table to file

   \param[in] out    File to write in
   \param[in] cnt_grp Counters group to write out
*/
static void table_write(FILE *out, int cnt_grp)
{
	int i;
	char buff[LINE_LEN];
	char *p;

	if (!cnt_group_desc[cnt_grp].table_entry_get)
		return;

	fprintf(out, "Page: %s\n", cnt_group_desc[cnt_grp].name);

	buff[0] = 0;
	p = cnt_group_desc[cnt_grp].table_entry_get(-1, buff);
	if(p == NULL && buff[0] != 0)
		p = buff;
	if(p)
		fprintf(out, "%s\n", p);

	for (i = 0; i < cnt_group_desc[cnt_grp].total; i++) {
		buff[0] = 0;
		p = cnt_group_desc[cnt_grp].table_entry_get(i, buff);
		if(p == NULL && buff[0] != 0)
			p = buff;
		if(p)
			fprintf(out, "%s\n", p);
	}
}

/** prompt line

   \param[in]     prefix Prompt prefix
   \param[in,out] str    Return entered string
*/
static void prompt(const char *prefix, char *str)
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

   \param[in] text Text to print
*/
static void notify(const char *text)
{
	/*attron(A_STANDOUT);*/
	mvaddstr(getmaxy(stdscr) - 1, 0, text);
	/*attroff(A_STANDOUT);*/
	clrtoeol();
	refresh();
	getch();
}

/** Get first line number */
static int first_line_get(void)
{
	char buff[LINE_LEN];
	int line;
	char *p;

	for (line = 0; line < CG.total; line++) {
		p = CG.table_entry_get(line, buff);

		if (!p)
			p = buff;

		if (is_filtered(p) == 0)
			return line;
	}

	return 0;
}

/** Get nth last line

   \param[in] nth nth line number
*/
static int last_line_get(int nth)
{
	char buff[LINE_LEN];
	int line;
	char *p;

	for (line = CG.total - 1; line >= 0; line--) {
		p = CG.table_entry_get(line, buff);

		if (!p)
			p = buff;

		if (is_filtered(p) == 0) {
			if (nth > 0)
				nth -= lines_num(p);

			if (nth <= 0)
				return line;
		}
	}

	return -1;
}

/** Get next line after given

   \param[in] start Start search from this line
*/
static int next_line_get(int start)
{
	char buff[LINE_LEN];
	int line;
	char *p;

	for (line = start + 1; line < CG.total - 1; line++) {
		p = CG.table_entry_get(line, buff);

		if (!p)
			p = buff;

		if (is_filtered(p) == 0)
			return line;
	}

	return -1;
}

/** Get next line before given

   \param[in] start Start search from this line
*/
static int prev_line_get(int start)
{
	char buff[LINE_LEN];
	int line;
	char *p;

	for (line = start - 1; line > 0; line--) {
		p = CG.table_entry_get(line, buff);

		if (!p)
			p = buff;

		if (is_filtered(p) == 0)
			return line;
	}

	return -1;
}

/** Get next page after given

   \param[in] start Start search from this line
*/
static int next_page_get(int start)
{
	char buff[LINE_LEN];
	int line;
	int page_lines = getmaxy(stdscr) - 2;
	char *p;

	for (line = start + 1; line < CG.total - 1; line++) {
		p = CG.table_entry_get(line, buff);

		if (!p)
			p = buff;

		if (is_filtered(p) == 0) {
			page_lines -= lines_num(p);

			if (page_lines <= 0) {
				return line;
			}
		}
	}

	return -1;
}

/** Get next page before given

   \param[in] start Start search from this line
*/
static int prev_page_get(int start)
{
	char buff[LINE_LEN];
	int line;
	int page_lines = getmaxy(stdscr) - 2;
	char *p;

	for (line = start - 1; line > 0; line--) {
		p = CG.table_entry_get(line, buff);

		if (!p)
			p = buff;

		if (is_filtered(p) == 0) {
			page_lines -= lines_num(p);

			if (page_lines <= 0) {
				return line;
			}
		}
	}

	return -1;
}

static void dump_all_tables(const int fd)
{
	unsigned int i;
	FILE *cnt_dump;

	cnt_dump = fopen("/tmp/gtop.txt", "w");
	if (!cnt_dump) {
		fprintf(stderr, "Can't save dump to /tmp/gtop.txt\n");
		return;
	}

	for (i = CG_MIN; i < CG_MAX; i++) {
		if (counters_fetch(fd, i) >= 0) {
			table_write(cnt_dump, i);
			fprintf(cnt_dump, "\n");
		}
	}

	fclose(cnt_dump);

	printf("Saved dump to /tmp/gtop.txt\n");
}

/** Count cursor position in percents */
static inline unsigned int pos_percent(unsigned int pos,
				       unsigned int total)
{
	if (pos == 0 || total == 0)
		return 0;

	return pos * 100 / total;
}

/** Return 1 if any counters group has been selected */
static int is_cnt_selected(void)
{
	return g_sel_cnt_grp != 0xFFFFFFFF;
}

/** Select new counters page */
static void cnt_select(unsigned int new_sel_cnt_grp)
{
	unsigned int prev_sel_cnt_grp = g_sel_cnt_grp;

	if(is_cnt_selected() &&
	   prev_sel_cnt_grp != new_sel_cnt_grp &&
	   cnt_group_desc[prev_sel_cnt_grp].table_leave)
			cnt_group_desc[prev_sel_cnt_grp].table_leave();

	g_sel_cnt_grp = new_sel_cnt_grp;

	if (is_cnt_selected() &&
	    prev_sel_cnt_grp != new_sel_cnt_grp &&
	    cnt_group_desc[new_sel_cnt_grp].table_enter)
		cnt_group_desc[new_sel_cnt_grp].table_enter();
}

/** Main window handler */
static void main_window_handle(void)
{
	int group_key = 0, key;
	unsigned int i, y, cols, rows;
	int line;
	char buff[LINE_LEN];
	struct timeval tv, upd_time;
	FILE *cnt_dump;
	int need_update = 1;
	int need_redraw = 1;
	char *p;
	struct onu_test_mode t;
	struct onu_cnt_reset reset;


	if(!is_cnt_selected())
		cnt_select(0);

	gettimeofday(&upd_time, 0);

	while (1) {
#ifdef SIGWINCH
		if (g_need_resize) {
			terminal_size_get(&cols, &rows);
			resizeterm(rows, cols);

			g_need_resize = 0;
		}
#endif

		if (!CG.table_entry_get || !CG.table_get) {
			sprintf(buff, "ERROR: Can't retrieve "
				"table data for %s; "
				"no handler defined", CG.name);
		} else {
			gettimeofday(&tv, 0);

			if ((unsigned int)tv.tv_sec == upd_time.tv_sec
			    + g_upd_delay / 1000) {
				if ((unsigned int)tv.tv_usec - upd_time.tv_usec
				    > g_upd_delay % 1000 * 1000) {
					upd_time = tv;
					need_update = 1;
					need_redraw = 1;
				}
			} else {
				if ((unsigned int)tv.tv_sec - upd_time.tv_sec
				    > g_upd_delay / 1000) {
					upd_time = tv;
					need_update = 1;
					need_redraw = 1;
				}
			}
		}

		if (need_update) {
			(void)counters_fetch(g_dev_fd, g_sel_cnt_grp);
			need_update = 0;
		}

		if (need_redraw) {
			buff[0] = 0;
			p = CG.table_entry_get(-1, buff);
			if(p == NULL) {
				if(buff[0] == 0)
					p = CG.name;
				else
					p = buff;
			}

			move(0, 0);
			attron(A_UNDERLINE);
			addstr(p);
			clrtoeol();
			attroff(A_UNDERLINE);

			/* data */
			for (line = CG.start, y = 1;
			     y + 1 < getmaxy(stdscr);
			     line++) {

				if (line >= CG.total) {
					move(y, 0);
					clrtoeol();
					y++;
					continue;
				}

				buff[0] = 0;
				p = CG.table_entry_get(line, buff);
				if (p == NULL && buff[0] != 0)
					p = buff;
				if (p && is_filtered(p) == 0) {
					move(y, 0);
					addstr(p);
					y += lines_num(p);
					clrtoeol();
				}
			}

			/* footer */
			mvaddstr(getmaxy(stdscr) - 1, 0,
				"Press ? or Ctrl-h for help");

			sprintf(buff,
				"%-30s                    Delay: %dms  %3d%%",
				CG.name,
				g_upd_delay,
				pos_percent(CG.start, CG.total));

			mvaddstr(getmaxy(stdscr) - 1,
				 getmaxx(stdscr) - (int)strlen(buff) - 1,
				 buff);

			clrtoeol();

			refresh();

			need_redraw = 0;
		}

		key = key_read();
		switch (key) {
		case 0:
			break;

		case KEY_ENTER:
			group_key = 0;
			break;

		case '/':
			prompt("/", g_filter);

			line = prev_line_get(CG.start);
			if (line >= 0) {
				CG.start = line;
			} else {
				CG.start = first_line_get();
			}

			break;

		case KEY_HOME:
			line = first_line_get();

			if (CG.start != line)
				CG.start = first_line_get();
			break;

		case KEY_END:
			line = last_line_get(getmaxy(stdscr) - 2);
			if (line >= 0 && CG.start != line)
				CG.start = line;
			break;

		case KEY_CTRL_X:
			shutdown(0);
			break;

		case KEY_CTRL_E:
		case KEY_DOWN:
			line = next_line_get(CG.start);
			if (line >= 0 && CG.start != line)
				CG.start = line;

			break;

		case KEY_CTRL_Y:
		case KEY_UP:
			line = prev_line_get(CG.start);
			if (line >= 0 && CG.start != line)
				CG.start = line;

			break;

		case KEY_CTRL_D:
		case KEY_NPAGE:
			line = next_page_get(CG.start);
			if (line >= 0 && CG.start != line)
				CG.start = line;

			break;

		case KEY_CTRL_U:
		case KEY_PPAGE:
			line = prev_page_get(CG.start);
			if (line >= 0 && CG.start != line)
				CG.start = line;
			else if (line < 0 && CG.start != 0)
				CG.start = 0;

			break;

		case KEY_CTRL_W:
			gettimeofday(&tv, 0);
			sprintf(buff, "/tmp/%lu_%lu_%s.txt", tv.tv_sec,
				tv.tv_usec, CG.name);

			cnt_dump = fopen(buff, "w");
			if (!cnt_dump) {
				clear();

				sprintf(buff, "Can't save counters to "
					"'/tmp/%lu_%lu_%s.txt'. "
					"Press any key to continue...",
					tv.tv_sec, tv.tv_usec, CG.name);
				notify(buff);

				clear();
				break;
			}

			table_write(cnt_dump, g_sel_cnt_grp);

			fclose(cnt_dump);

			clear();

			sprintf(buff, "Saved to '/tmp/%lu_%lu_%s.txt'. "
				"Press any key to continue...",
				tv.tv_sec, tv.tv_usec, CG.name);
			notify(buff);

			clear();
			break;

		case KEY_CTRL_A:
			gettimeofday(&tv, 0);
			sprintf(buff, "/tmp/%lu_%lu.txt", tv.tv_sec, tv.tv_usec);

			clear();
			mvaddstr(getmaxy(stdscr) - 1, 0,
				 "Fetching all counters...");
			refresh();

			cnt_dump = fopen(buff, "w");
			if (!cnt_dump) {
				clear();

				sprintf(buff, "Can't save counters to "
					"'/tmp/%lu_%lu.txt'. "
					"Press any key to continue...",
					tv.tv_sec, tv.tv_usec);
				notify(buff);

				clear();
				break;
			}

			for (i = CG_MIN; i < CG_MAX; i++) {
				if (counters_fetch(g_dev_fd, i) >= 0) {
					table_write(cnt_dump, i);
					fprintf(cnt_dump, "\n");
				}
			}

			fclose(cnt_dump);

			clear();

			sprintf(buff, "Saved to '/tmp/%lu_%lu.txt'. "
				"Press any key to continue...",
				tv.tv_sec, tv.tv_usec);
			notify(buff);

			clear();
			break;

		case KEY_CTRL_B:
			strcpy(t.mode, ONU_TESTMODE_RAW_KEY"=0");
			onu_iocmd(g_dev_fd, FIO_ONU_TEST_MODE_SET, &t, sizeof(t));
			break;

		case KEY_CTRL_V:
			strcpy(t.mode, ONU_TESTMODE_RAW_KEY"=1");
			onu_iocmd(g_dev_fd, FIO_ONU_TEST_MODE_SET, &t, sizeof(t));
			break;

		case KEY_CTRL_R:
			reset.curr = 1;
			onu_iocmd(g_dev_fd, FIO_ONU_COUNTERS_RESET, &reset, sizeof(reset));
			break;

		default:
			for (i = CG_MIN; i < CG_MAX; i++) {
				if (group_key == cnt_group_desc[i].group_key
				    && key == cnt_group_desc[i].key) {
					cnt_select(i);
					need_update = 1;

					break;
				}
			}

			if (!group_key) {
				for (i = CG_MIN; i < CG_MAX; i++) {
					if (cnt_group_desc[i].group_key
					    == key) {
						group_key = key;
						break;
					}
				}
			} else {
				group_key = 0;
			}

			break;
		}

		if (key)
			need_redraw = 1;
	}
}

/** Print help */
static void help_print(char const *name)
{
	unsigned int u;
	if (name == NULL)
		name = "gtop";

	printf("%s V" GTOP_VERSION " (compiled on "
	       __DATE__ " " __TIME__ ")\n", name);

	printf("Usage: %s [options]"
	       "\n\n"
	       "Options:\n"
	       "\t-b, --batch       Start in `Batch mode` \n"
	       "\t-d, --delay <ms>  Counters update delay\n"
	       "\t-g, --group <grp> Show specified counters upon startup \n",
	       name);

	printf("\t                  "
	       "Possible group values(use either symbol or full name):\n");
	for (u = CG_MIN; u < CG_MAX; u++) {
		if (cnt_group_desc[u].group_key == 0)
			printf("\t                     %c - %s\n",
			       cnt_group_desc[u].key,
			       cnt_group_desc[u].name);
		else
			printf("\t                     %s\n",
			       cnt_group_desc[u].name);
	}

	printf("\n"
	       "\t-r, --remote-ip <ip>[:<port>] Remote ONU IP address \n"
	       "\t-h, --help        Print help (this message)\n"
	       "\t-v, --version     Print version information\n");
}

/** Parse command line arguments

   \param[in] argc Arguments count
   \param[in] argv Array of arguments
*/
static int arguments_parse(int argc, char *argv[])
{
	int c;
	int option;
	unsigned int u;

	static struct option opt_str[] = {
		{ "help", no_argument, 0, 'h' },
		{ "version", no_argument, 0, 'v' },
		{ "batch", no_argument, 0, 'b' },
		{ "delay", required_argument, 0, 'd' },
		{ "group", required_argument, 0, 'g' },
		{ "remote-ip", required_argument, 0, 'r' },
		{ NULL, no_argument, 0, 'd' }
	};

	static const char long_opts[] = "hvbd:g:r:";

	do {
		c = getopt_long(argc, argv, long_opts, opt_str, &option);

		if (c == -1)
			return 0;

		switch (c) {
		case 'h':
			help_print((char *)basename(argv[0]));

			return 1;

		case 'v':
			printf("%s V" GTOP_VERSION
			       " (compiled on "
			       __DATE__ " " __TIME__ ")\n", basename(argv[0]));

			return 1;

		case 'b':
			g_batch_mode = 1;

			break;

		case 'd':
			g_upd_delay = (unsigned int)atoi(optarg);

			if (g_upd_delay == 0) {
				fprintf(stderr,
					"Invalid value for option 'd'\n");
				return 1;
			}

			break;

		case 'g':
			cnt_select(0xFFFFFFFF);
			for (u = CG_MIN; u < CG_MAX; u++) {
				if (strlen(optarg) == 1) {
					if (cnt_group_desc[u].group_key == 0
					&& cnt_group_desc[u].key
					    == optarg[0]) {
						cnt_select(u);
						break;
					}
				} else {
					if (strcmp(cnt_group_desc[u].name,
						   optarg) == 0) {
						cnt_select(u);
						break;
					}
				}
			}

			if (!is_cnt_selected()) {
				fprintf(stderr,
					"Invalid value for option 'g'\n");
				return 1;
			}

			break;

#ifdef INCLUDE_REMOTE_ONU
		case 'r':
			if(optarg && (strlen(optarg)<(MAX_PATH-1))) {
				strcpy(g_remote, optarg);
			}
			break;
#endif

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
int main(int argc, char *argv[])
{
#ifdef INCLUDE_REMOTE_ONU
	g_remote[0] = 0;
#endif

	if (arguments_parse(argc, argv))
		return 0;

#ifdef INCLUDE_REMOTE_ONU

	if (g_remote[0] == 0 && remote_default_ip_get()) {
		strncpy(&g_remote[0],
			remote_default_ip_get(),
			sizeof(g_remote));
		g_remote[sizeof(g_remote) - 1] = '\0';
	}

	if (g_remote[0])
		remote_init(&g_remote[0], 2);
#endif

#ifndef ONU_SIMULATION
	g_dev_fd = onu_open(ONU_DEVICE_PATH);
	if (g_dev_fd < 0) {
		fprintf(stderr, "Can't open device " ONU_DEVICE_PATH "\n");
		return 1;
	}
#endif

	if (onu_iocmd(g_dev_fd, FIO_GPE_CAPABILITY_GET,
		&g_capability, sizeof(g_capability)) != 0) {
		fprintf(stderr, "Can't get device capabilities\n");
		return 1;
	}

	group_init(true);

	if (g_batch_mode == 1) {
		if(is_cnt_selected()) {
			if(g_sel_cnt_grp >= CG_MAX)
				cnt_select(0);
			else
				cnt_select(g_sel_cnt_grp);

			(void)counters_fetch(g_dev_fd, g_sel_cnt_grp);
			table_write(stdout, g_sel_cnt_grp);
		} else {
			dump_all_tables(g_dev_fd);
		}

#ifndef ONU_SIMULATION
		onu_close(g_dev_fd);
#endif
	} else {
		signal(SIGINT, shutdown);
		signal(SIGSEGV, shutdown);

		initscr();

		keypad(stdscr, TRUE);
		nonl();
		cbreak();
		noecho();
		curs_set(0);

#ifdef SIGWINCH
		signal(SIGWINCH, resize);
#endif
		main_window_handle();

		shutdown(0);
	}

	return 0;
}
