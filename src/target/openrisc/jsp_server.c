/***************************************************************************
 *   Copyright (C) 2005 by Dominic Rath                                    *
 *   Dominic.Rath@gmx.de                                                   *
 *                                                                         *
 *   Copyright (C) 2007-2010 Øyvind Harboe                                 *
 *   oyvind.harboe@zylin.com                                               *
 *                                                                         *
 *   Copyright (C) 2008 by Spencer Oliver                                  *
 *   spen@spen-soft.co.uk                                                  *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "jsp_server.h"
#include <target/target_request.h>
#include <helper/configuration.h>

static const char *jsp_port;

/**A skim of the relevant RFCs suggests that if my application simply sent the 
 * characters IAC DONT LINEMODE (\377\376\042) as soon as the client connects, 
 * the client should be forced into character mode. However it doesn't make any difference.
 */
 
static char *negotiate =
	"\xFF\xFB\x03"			/* IAC WILL Suppress Go Ahead */
	"\xFF\xFB\x01"			/* IAC WILL Echo */
	"\xFF\xFD\x03"			/* IAC DO Suppress Go Ahead */
	"\xFF\xFE\x01";			/* IAC DON'T Echo */

#define CTRL(c) (c - '@')
#define TELNET_HISTORY	".openocd_history"

/* The only way we can detect that the socket is closed is the first time
 * we write to it, we will fail. Subsequent write operations will
 * succeed. Shudder!
 */
static int telnet_write(struct connection *connection, const void *data,
	int len)
{
	struct telnet_connection *t_con = connection->priv;
	if (t_con->closed)
		return ERROR_SERVER_REMOTE_CLOSED;

	if (connection_write(connection, data, len) == len)
		return ERROR_OK;
	t_con->closed = 1;
	return ERROR_SERVER_REMOTE_CLOSED;
}

static int telnet_prompt(struct connection *connection)
{
	struct telnet_connection *t_con = connection->priv;

	return telnet_write(connection, t_con->prompt, strlen(t_con->prompt));
}

static int telnet_outputline(struct connection *connection, const char *line)
{
	int len;

	/* process lines in buffer */
	while (*line) {
		char *line_end = strchr(line, '\n');

		if (line_end)
			len = line_end-line;
		else
			len = strlen(line);

		telnet_write(connection, line, len);
		if (line_end) {
			telnet_write(connection, "\r\n", 2);
			line += len + 1;
		} else
			line += len;
	}

	return ERROR_OK;
}

static int telnet_output(struct command_context *cmd_ctx, const char *line)
{
	struct connection *connection = cmd_ctx->output_handler_priv;

	return telnet_outputline(connection, line);
}

static void telnet_log_callback(void *priv, const char *file, unsigned line,
	const char *function, const char *string)
{
	struct connection *connection = priv;
	struct telnet_connection *t_con = connection->priv;
	int i;

	/* if there is no prompt, simply output the message */
	if (t_con->line_cursor < 0) {
		telnet_outputline(connection, string);
		return;
	}

	/* clear the command line */
	for (i = strlen(t_con->prompt) + t_con->line_size; i > 0; i -= 16)
		telnet_write(connection, "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b", i > 16 ? 16 : i);
	for (i = strlen(t_con->prompt) + t_con->line_size; i > 0; i -= 16)
		telnet_write(connection, "                ", i > 16 ? 16 : i);
	for (i = strlen(t_con->prompt) + t_con->line_size; i > 0; i -= 16)
		telnet_write(connection, "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b", i > 16 ? 16 : i);

	/* output the message */
	telnet_outputline(connection, string);

	/* put the command line to its previous state */
	telnet_prompt(connection);
	telnet_write(connection, t_con->line, t_con->line_size);
	for (i = t_con->line_size; i > t_con->line_cursor; i--)
		telnet_write(connection, "\b", 1);
}

static void telnet_load_history(struct telnet_connection *t_con)
{
	FILE *histfp;
	char buffer[TELNET_BUFFER_SIZE];
	int i = 0;

	char *history = get_home_dir(TELNET_HISTORY);

	if (history == NULL) {
		LOG_INFO("unable to get user home directory, telnet history will be disabled");
		return;
	}

	histfp = fopen(history, "rb");

	if (histfp) {

		while (fgets(buffer, sizeof(buffer), histfp) != NULL) {

			char *p = strchr(buffer, '\n');
			if (p)
				*p = '\0';
			if (buffer[0] && i < TELNET_LINE_HISTORY_SIZE)
				t_con->history[i++] = strdup(buffer);
		}

		t_con->next_history = i;
		t_con->next_history %= TELNET_LINE_HISTORY_SIZE;
		/* try to set to last entry - 1, that way we skip over any exit/shutdown cmds */
		t_con->current_history = t_con->next_history > 0 ? i - 1 : 0;
		fclose(histfp);
	}

	free(history);
}

static void telnet_save_history(struct telnet_connection *t_con)
{
	FILE *histfp;
	int i;
	int num;

	char *history = get_home_dir(TELNET_HISTORY);

	if (history == NULL) {
		LOG_INFO("unable to get user home directory, telnet history will be disabled");
		return;
	}

	histfp = fopen(history, "wb");

	if (histfp) {

		num = TELNET_LINE_HISTORY_SIZE;
		i = t_con->current_history + 1;
		i %= TELNET_LINE_HISTORY_SIZE;

		while (t_con->history[i] == NULL && num > 0) {
			i++;
			i %= TELNET_LINE_HISTORY_SIZE;
			num--;
		}

		if (num > 0) {
			for (; num > 0; num--) {
				fprintf(histfp, "%s\n", t_con->history[i]);
				i++;
				i %= TELNET_LINE_HISTORY_SIZE;
			}
		}
		fclose(histfp);
	}

	free(history);
}

int jsp_poll_read(void *priv)
{
	struct jsp_service *jsp_service = (struct jsp_service *)priv;
	int out_len = 0;
	int in_len;
	unsigned char out_buffer[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	unsigned char in_buffer[10];

	if (!jsp_service->connection)
		return ERROR_FAIL;

	or1k_adv_jtag_jsp_xfer(jsp_service->jtag_info, &out_len, out_buffer, &in_len, in_buffer);
	if (in_len)
		telnet_write(jsp_service->connection, in_buffer, in_len);

	return 0;
}

static int jsp_new_connection(struct connection *connection)
{
	struct telnet_connection *telnet_connection = malloc(sizeof(struct telnet_connection));
	struct jsp_service *jsp_service = connection->service->priv;
	int i;

	connection->priv = telnet_connection;

	/* initialize telnet connection information */
	telnet_connection->closed = 0;
	telnet_connection->line_size = 0;
	telnet_connection->line_cursor = 0;
	telnet_connection->option_size = 0;
	telnet_connection->prompt = strdup("> ");
	telnet_connection->state = TELNET_STATE_DATA;

	/* output goes through telnet connection */
	command_set_output_handler(connection->cmd_ctx, telnet_output, connection);

	/* negotiate telnet options */
	telnet_write(connection, negotiate, strlen(negotiate));

	/* print connection banner */
	if (jsp_service->banner) {
		telnet_write(connection, jsp_service->banner, strlen(jsp_service->banner));
		telnet_write(connection, "\r\n", 2);
	}

	/* the prompt is always placed at the line beginning */
	telnet_write(connection, "\r", 1);
	telnet_prompt(connection);

	/* initialize history */
	for (i = 0; i < TELNET_LINE_HISTORY_SIZE; i++)
		telnet_connection->history[i] = NULL;
	telnet_connection->next_history = 0;
	telnet_connection->current_history = 0;
	telnet_load_history(telnet_connection);

	log_add_callback(telnet_log_callback, connection);

	jsp_service->connection = connection;

	int retval = target_register_timer_callback(&jsp_poll_read, 1, 1, jsp_service);
	if (ERROR_OK != retval)
		return retval;

	return ERROR_OK;
}

static void telnet_clear_line(struct connection *connection,
	struct telnet_connection *t_con)
{
	/* move to end of line */
	if (t_con->line_cursor < t_con->line_size)
		telnet_write(connection,
			t_con->line + t_con->line_cursor,
			t_con->line_size - t_con->line_cursor);

	/* backspace, overwrite with space, backspace */
	while (t_con->line_size > 0) {
		telnet_write(connection, "\b \b", 3);
		t_con->line_size--;
	}
	t_con->line_cursor = 0;
}

static void telnet_history_go(struct connection *connection, int idx)
{
	struct telnet_connection *t_con = connection->priv;

	if (t_con->history[idx]) {
		telnet_clear_line(connection, t_con);
		t_con->line_size = strlen(t_con->history[idx]);
		t_con->line_cursor = t_con->line_size;
		memcpy(t_con->line, t_con->history[idx], t_con->line_size);
		telnet_write(connection, t_con->line, t_con->line_size);
		t_con->current_history = idx;
	}
	t_con->state = TELNET_STATE_DATA;
}

static void telnet_history_up(struct connection *connection)
{
	struct telnet_connection *t_con = connection->priv;

	int last_history = (t_con->current_history > 0) ?
				t_con->current_history - 1 :
				TELNET_LINE_HISTORY_SIZE-1;
	telnet_history_go(connection, last_history);
}

static void telnet_history_down(struct connection *connection)
{
	struct telnet_connection *t_con = connection->priv;

	int next_history = (t_con->current_history + 1) % TELNET_LINE_HISTORY_SIZE;
	telnet_history_go(connection, next_history);
}

static int jsp_input(struct connection *connection)
{
	int bytes_read;
	//int retval;
	unsigned char buffer[TELNET_BUFFER_SIZE];
	unsigned char *buf_p;
	struct telnet_connection *t_con = connection->priv;
	struct jsp_service *jsp_service = connection->service->priv;

	bytes_read = connection_read(connection, buffer, TELNET_BUFFER_SIZE);

	if (bytes_read == 0)
		return ERROR_SERVER_REMOTE_CLOSED;
	else if (bytes_read == -1) {
		LOG_ERROR("error during read: %s", strerror(errno));
		return ERROR_SERVER_REMOTE_CLOSED;
	}

	buf_p = buffer;
	while (bytes_read) {
		switch (t_con->state) {
			case TELNET_STATE_DATA:
				if (*buf_p == 0xff)
					t_con->state = TELNET_STATE_IAC;
				else {
					int out_len = 1;
					int in_len;
					unsigned char in_buffer[10];
					or1k_adv_jtag_jsp_xfer(jsp_service->jtag_info, &out_len, buf_p, &in_len, in_buffer);
					if (in_len)
						telnet_write(connection, in_buffer, in_len);
				}
				break;
			case TELNET_STATE_IAC:
				switch (*buf_p) {
				case 0xfe:
					t_con->state = TELNET_STATE_DONT;
					break;
				case 0xfd:
					t_con->state = TELNET_STATE_DO;
					break;
				case 0xfc:
					t_con->state = TELNET_STATE_WONT;
					break;
				case 0xfb:
					t_con->state = TELNET_STATE_WILL;
					break;
				}
				break;
			case TELNET_STATE_SB:
				break;
			case TELNET_STATE_SE:
				break;
			case TELNET_STATE_WILL:
			case TELNET_STATE_WONT:
			case TELNET_STATE_DO:
			case TELNET_STATE_DONT:
				t_con->state = TELNET_STATE_DATA;
				break;
			case TELNET_STATE_ESCAPE:
				if (t_con->last_escape == '[') {
					if (*buf_p == 'D') {	/* cursor left */
						if (t_con->line_cursor > 0) {
							telnet_write(connection, "\b", 1);
							t_con->line_cursor--;
						}
						t_con->state = TELNET_STATE_DATA;
					} else if (*buf_p == 'C') {	/* cursor right */
						if (t_con->line_cursor < t_con->line_size)
							telnet_write(connection,
									t_con->line + t_con->line_cursor++, 1);
						t_con->state = TELNET_STATE_DATA;
					} else if (*buf_p == 'A') {	/* cursor up */
						telnet_history_up(connection);
					} else if (*buf_p == 'B') {	/* cursor down */
						telnet_history_down(connection);
					} else if (*buf_p == '3')
						t_con->last_escape = *buf_p;
					else
						t_con->state = TELNET_STATE_DATA;
				} else if (t_con->last_escape == '3') {
					/* Remove character */
					if (*buf_p == '~') {
						if (t_con->line_cursor < t_con->line_size) {
							int i;
							t_con->line_size--;
							/* remove char from line buffer */
							memmove(t_con->line + t_con->line_cursor,
									t_con->line + t_con->line_cursor + 1,
									t_con->line_size - t_con->line_cursor);

							/* print remainder of buffer */
							telnet_write(connection, t_con->line + t_con->line_cursor,
									t_con->line_size - t_con->line_cursor);
							/* overwrite last char with whitespace */
							telnet_write(connection, " \b", 2);

							/* move back to cursor position*/
							for (i = t_con->line_cursor; i < t_con->line_size; i++)
								telnet_write(connection, "\b", 1);
						}

						t_con->state = TELNET_STATE_DATA;
					} else
						t_con->state = TELNET_STATE_DATA;
				} else if (t_con->last_escape == '\x00') {
					if (*buf_p == '[')
						t_con->last_escape = *buf_p;
					else
						t_con->state = TELNET_STATE_DATA;
				} else {
					LOG_ERROR("BUG: unexpected value in t_con->last_escape");
					t_con->state = TELNET_STATE_DATA;
				}

				break;
			default:
				LOG_ERROR("unknown telnet state");
				exit(-1);
		}

		bytes_read--;
		buf_p++;
	}

	return ERROR_OK;
}

static int jsp_connection_closed(struct connection *connection)
{
	struct telnet_connection *t_con = connection->priv;
	struct jsp_service *jsp_service = connection->service->priv;
	int i;

	log_remove_callback(telnet_log_callback, connection);

	if (t_con->prompt) {
		free(t_con->prompt);
		t_con->prompt = NULL;
	}

	/* save telnet history */
	telnet_save_history(t_con);

	for (i = 0; i < TELNET_LINE_HISTORY_SIZE; i++) {
		if (t_con->history[i]) {
			free(t_con->history[i]);
			t_con->history[i] = NULL;
		}
	}

	int retval = target_unregister_timer_callback(&jsp_poll_read, jsp_service);
	if (ERROR_OK != retval)
		return retval;

	/* if this connection registered a debug-message receiver delete it */
	delete_debug_msg_receiver(connection->cmd_ctx, NULL);

	if (connection->priv) {
		free(connection->priv);
		connection->priv = NULL;
	} else
		LOG_ERROR("BUG: connection->priv == NULL");

	return ERROR_OK;
}

int jsp_init(struct or1k_jtag *jtag_info, char *banner)
{

	struct jsp_service *jsp_service = malloc(sizeof(struct jsp_service));

	jsp_service->banner = banner;
	jsp_service->jtag_info = jtag_info;

	jsp_port = strdup("9999");

	return add_service("jsp",
		jsp_port,
		1,
		jsp_new_connection,
		jsp_input,
		jsp_connection_closed,
		jsp_service);
}

/* daemon configuration command jsp_port */
COMMAND_HANDLER(handle_jsp_port_command)
{
	return CALL_COMMAND_HANDLER(server_pipe_command, &jsp_port);
}

COMMAND_HANDLER(handle_exit_command)
{
	return ERROR_COMMAND_CLOSE_CONNECTION;
}

static const struct command_registration jsp_command_handlers[] = {
	{
		.name = "exit",
		.handler = handle_exit_command,
		.mode = COMMAND_EXEC,
		.usage = "",
		.help = "exit telnet session",
	},
	{
		.name = "jsp_port",
		.handler = handle_jsp_port_command,
		.mode = COMMAND_ANY,
		.help = "Specify port on which to listen "
			"for incoming telnet connections.  "
			"Read help on 'gdb_port'.",
		.usage = "[port_num]",
	},
	COMMAND_REGISTRATION_DONE
};

int jsp_register_commands(struct command_context *cmd_ctx)
{
	return register_commands(cmd_ctx, NULL, jsp_command_handlers);
}
