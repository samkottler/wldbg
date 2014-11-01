/*
 * Copyright (c) 2014 Marek Chalupa
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <sys/signalfd.h>

#include "wldbg.h"
#include "wldbg-pass.h"
#include "interactive.h"
#include "resolve.h"
#include "passes.h"
#include "print.h"

/* defined in interactive-commands.c */
int
cmd_quit(struct wldbg_interactive *wldbgi,
		struct message *message, char *buf);

static void
query_user(struct wldbg_interactive *wldbgi, struct message *message)
{
	char buf[1024];
	int ret;

	while (1) {
		if (wldbgi->wldbg->flags.exit
			|| wldbgi->wldbg->flags.error)
			break;

		printf("(wldbg) ");

		if (fgets(buf, sizeof buf, stdin) == NULL) {
			if(cmd_quit(wldbgi, NULL, NULL) == CMD_END_QUERY)
				break;
			else
				continue;
		}

		ret = run_command(buf, wldbgi, message);

		if (ret == CMD_END_QUERY)
			break;
		else if (ret == CMD_CONTINUE_QUERY)
			continue;

		if (buf[0] != '\n')
			printf("Unknown command: %s", buf);
	}
}

static int
process_message(struct wldbg_interactive *wldbgi, struct message *message)
{
	/* print message's description
	 * This is default behaviour. XXX add possibility to
	 * turn it off */
	print_message(wldbgi->wldbg, message);

	if (wldbgi->stop) {
		dbg("Stopped at message no. %lu from %s\n",
			message->from == SERVER ?
				wldbgi->statistics.server_msg_no :
				wldbgi->statistics.client_msg_no,
			message->from == SERVER ?
				"server" : "client");
		/* reset flag */
		wldbgi->stop = 0;
		query_user(wldbgi, message);
	}

	return 0;
}

static int
process_interactive(void *user_data, struct message *message)
{
	struct wldbg_interactive *wldbgi = user_data;

	vdbg("Mesagge from %s\n",
		message->from == SERVER ? "SERVER" : "CLIENT");

	if (message->from == SERVER)
		++wldbgi->statistics.server_msg_no;
	else
		++wldbgi->statistics.client_msg_no;

	if (!wldbgi->skip_first_query
		&& (wldbgi->statistics.server_msg_no
		+ wldbgi->statistics.client_msg_no == 1)) {
		printf("Stopped on the first message\n");
		wldbgi->stop = 1;
	}

	process_message(wldbgi, message);

	/* This is always the last pass. Even when user will add
	 * some passes interactively, they will be added before
	 * this one */
	return PASS_STOP;
}

static void
wldbgi_destory(void *data)
{
	struct wldbg_interactive *wldbgi = data;

	dbg("Destroying wldbgi\n");

	wldbgi->wldbg->flags.exit = 1;

	if (wldbgi->client.path)
		free(wldbgi->client.path);

	free(wldbgi);
}

static int
handle_sigint(int fd, void *data)
{
	size_t len;
	struct signalfd_siginfo si;
	struct wldbg_interactive *wldbgi = data;

	len = read(fd, &si, sizeof si);
	if (len != sizeof si) {
		fprintf(stderr, "reading signal's fd failed\n");
		return -1;
	}

	vdbg("Wldbgi: Got interrupt (SIGINT)\n");
	wldbgi->stop = 1;

	putchar('\n');

	return 1;
}

int
run_interactive(struct wldbg *wldbg, int argc, const char *argv[])
{
	struct pass *pass;
	struct wldbg_interactive *wldbgi;
	sigset_t signals;

	dbg("Starting interactive mode.\n");

	wldbgi = malloc(sizeof *wldbgi);
	if (!wldbgi)
		return -1;

	memset(wldbgi, 0, sizeof *wldbgi);
	wldbgi->wldbg = wldbg;

	pass = alloc_pass("interactive");
	if (!pass)
		goto err_wldbgi;

	wl_list_insert(wldbg->passes.next, &pass->link);

	pass->wldbg_pass.init = NULL;
	/* XXX ! */
	pass->wldbg_pass.help = NULL;
	pass->wldbg_pass.destroy = wldbgi_destory;
	pass->wldbg_pass.server_pass = process_interactive;
	pass->wldbg_pass.client_pass = process_interactive;
	pass->wldbg_pass.user_data = wldbgi;
	pass->wldbg_pass.description
		= "Interactive pass for wldbg (hardcoded)";
	pass->wldbg_pass.flags = WLDBG_PASS_LOAD_ONCE;

	wldbg->flags.one_by_one = 1;

	/* remove default SIGINT handler */
	sigdelset(&wldbg->handled_signals, SIGINT);
	wldbg->signals_fd = signalfd(wldbg->signals_fd, &wldbg->handled_signals,
					SFD_CLOEXEC);

	if (wldbg->signals_fd == -1)
		goto err_pass;

	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);

	/* set our own signal handlers */
	wldbgi->sigint_fd = signalfd(-1, &signals, SFD_CLOEXEC);

	if (wldbgi->sigint_fd == -1)
		goto err_pass;

	vdbg("Adding interactive SIGINT handler (fd %d)\n", wldbgi->sigint_fd);
	if (wldbg_monitor_fd(wldbg, wldbgi->sigint_fd,
				handle_sigint, wldbgi) < 0)
		goto err_pass;

	if (argc == 0) {
		query_user(wldbgi, NULL);
		return 0;
	}

	/* TODO use getopt */
	if (strcmp(argv[0], "--") == 0) {
		wldbg->client.path = argv[1];
		wldbg->client.argc = argc - 1;
		wldbg->client.argv = (char * const *) argv + 2;
	} else {
		wldbg->client.path = argv[0];
		wldbg->client.argc = argc;
		wldbg->client.argv = (char * const *) argv + 1;
	}

	return 0;

err_pass:
		dealloc_pass(pass);
err_wldbgi:
		free(wldbgi);

		return -1;
}