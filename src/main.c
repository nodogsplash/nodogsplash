/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/** @internal
  @file main.c
  @brief Main loop
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
  @author Copyright (C) 2008 Paul Kube <nodogsplash@kokoro.ucsd.edu>
 */



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <arpa/inet.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include "common.h"
#include "http_microhttpd.h"
#include "http_microhttpd_utils.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "main.h"
#include "commandline.h"
#include "auth.h"
#include "client_list.h"
#include "ndsctl_thread.h"
#include "fw_iptables.h"
#include "util.h"

#include <microhttpd.h>

// Check for libmicrohttp version >= 0.9.51
#if MHD_VERSION < 0x00095100
#error libmicrohttp version >= 0.9.51 required
#endif

/** XXX Ugly hack
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_client_check = 0;

/* The internal web server */
struct MHD_Daemon * webserver = NULL;

/* Time when nodogsplash started  */
time_t started_time = 0;

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * parent process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
	int	status;
	pid_t rc;

	debug(LOG_DEBUG, "SIGCHLD handler: Trying to reap a child");

	rc = waitpid(-1, &status, WNOHANG | WUNTRACED);

	if (rc == -1) {
		if (errno == ECHILD) {
			debug(LOG_DEBUG, "SIGCHLD handler: waitpid(): No child exists now.");
		} else {
			debug(LOG_ERR, "SIGCHLD handler: Error reaping child (waitpid() returned -1): %s", strerror(errno));
		}
		return;
	}

	if (WIFEXITED(status)) {
		debug(LOG_DEBUG, "SIGCHLD handler: Process PID %d exited normally, status %d", (int)rc, WEXITSTATUS(status));
		return;
	}

	if (WIFSIGNALED(status)) {
		debug(LOG_DEBUG, "SIGCHLD handler: Process PID %d exited due to signal %d", (int)rc, WTERMSIG(status));
		return;
	}

	debug(LOG_DEBUG, "SIGCHLD handler: Process PID %d changed state, status %d not exited, ignoring", (int)rc, status);
	return;
}

/** Exits cleanly after cleaning up the firewall.
 *  Use this function anytime you need to exit after firewall initialization */
void
termination_handler(int s)
{
	static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;

	debug(LOG_NOTICE, "Handler for termination caught signal %d", s);

	/* Makes sure we only call iptables_fw_destroy() once. */
	if (pthread_mutex_trylock(&sigterm_mutex)) {
		debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
		pthread_exit(NULL);
	} else {
		debug(LOG_INFO, "Cleaning up and exiting");
	}

	auth_client_deauth_all();

	debug(LOG_INFO, "Flushing firewall rules...");
	iptables_fw_destroy();

	/* XXX Hack
	 * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
	 * termination handler) from happening so we need to explicitly kill the threads
	 * that use that
	 */
	if (tid_client_check) {
		debug(LOG_INFO, "Explicitly killing the fw_counter thread");
		pthread_kill(tid_client_check, SIGKILL);
	}

	debug(LOG_NOTICE, "Exiting...");
	exit(s == 0 ? 1 : 0);
}


/** @internal
 * Registers all the signal handlers
 */
static void
init_signals(void)
{
	struct sigaction sa;

	debug(LOG_DEBUG, "Setting SIGCHLD handler to sigchld_handler()");
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGPIPE */
	/* This is done so that when libhttpd does a socket operation on
	 * a disconnected socket (i.e.: Broken Pipes) we catch the signal
	 * and do nothing. The alternative is to exit. SIGPIPE are harmless
	 * if not desirable.
	 */
	debug(LOG_DEBUG, "Setting SIGPIPE  handler to SIG_IGN");
	sa.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	debug(LOG_DEBUG, "Setting SIGTERM, SIGQUIT, SIGINT  handlers to termination_handler()");
	sa.sa_handler = termination_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	/* Trap SIGTERM */
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGQUIT */
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}

	/* Trap SIGINT */
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		debug(LOG_ERR, "sigaction(): %s", strerror(errno));
		exit(1);
	}
}

/**@internal
 * Main execution loop
 */
static void
main_loop(void)
{
	int result = 0;
	pthread_t tid;
	s_config *config;
	char msg[255] = {0};
	char *fasurl = NULL;
	char *fasssl = NULL;
	char *fashid = NULL;
	char *phpcmd = NULL;
	char *preauth_dir = NULL;
	struct stat sb;
	char loginscript[] = "/usr/lib/nodogsplash/login.sh";
	time_t sysuptime;

	config = config_get_config();

	sysuptime = get_system_uptime ();
	debug(LOG_INFO, "main: System Uptime is %li seconds", sysuptime);

	/* Set the time when nodogsplash started */
	if (!started_time) {
		debug(LOG_INFO, "Setting started_time");
		started_time = time(NULL);
	} else if (started_time < (time(NULL) - sysuptime)) {
		debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
		started_time = time(NULL);
	}

	/* If we don't have the Gateway IP address, get it. Exit on failure. */
	if (!config->gw_ip) {
		debug(LOG_DEBUG, "Finding IP address of %s", config->gw_interface);
		config->gw_ip = get_iface_ip(config->gw_interface, config->ip6);
		if (!config->gw_ip) {
			debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->gw_interface);
			exit(1);
		}
	}

	/* format gw_address accordingly depending on if gw_ip is v4 or v6 */
	const char *ipfmt = config->ip6 ? "[%s]:%d" : "%s:%d";
	safe_asprintf(&config->gw_address, ipfmt, config->gw_ip, config->gw_port);

	if ((config->gw_mac = get_iface_mac(config->gw_interface)) == NULL) {
		debug(LOG_ERR, "Could not get MAC address information of %s, exiting...", config->gw_interface);
		exit(1);
	}
	debug(LOG_NOTICE, "Detected gateway %s at %s (%s)", config->gw_interface, config->gw_ip, config->gw_mac);

	/* Initializes the web server */
	if ((webserver = MHD_start_daemon(MHD_USE_EPOLL_INTERNALLY | MHD_USE_TCP_FASTOPEN,
							config->gw_port,
							NULL, NULL,
							libmicrohttpd_cb, NULL,
							MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 120,
							MHD_OPTION_LISTENING_ADDRESS_REUSE, 1,
							MHD_OPTION_UNESCAPE_CALLBACK, unescape,
							MHD_OPTION_END)) == NULL) {
		debug(LOG_ERR, "Could not create web server: %s", strerror(errno));
		exit(1);
	}
	/* TODO: set listening socket */
	debug(LOG_NOTICE, "Created web server on %s", config->gw_address);

	if (config->login_option_enabled > 0) {
		debug(LOG_NOTICE, "Login option is Enabled.\n");
		if (!((stat(loginscript, &sb) == 0) && S_ISREG(sb.st_mode) && (sb.st_mode & S_IXUSR))) {
			debug(LOG_ERR, "Login script does not exist or is not executeable: %s", loginscript);
			debug(LOG_ERR, "Exiting...");
			exit(1);
		} else {
			config->preauth = loginscript;
		}

	} else {
		debug(LOG_NOTICE, "Using config options for FAS or Templated Splash.\n");
	}

	if (config->preauth) {
		debug(LOG_NOTICE, "Preauth is Enabled - Overiding FAS configuration.\n");
		debug(LOG_NOTICE, "Preauth Script is %s\n", config->preauth);

		//override all other FAS settings
		config->fas_remoteip = safe_strdup(config->gw_ip);
		config->fas_remotefqdn = NULL;
		config->fas_port = config->gw_port;
		safe_asprintf(&preauth_dir, "/%s/", config->preauthdir);
		config->fas_path = safe_strdup(preauth_dir);
		config->fas_secure_enabled = 1;
		free(preauth_dir);
	}

	if (config->fas_port) {

		if (config->fas_remoteip) {
			if (is_addr(config->fas_remoteip) == 1) {
				debug(LOG_INFO, "fasremoteip - %s - is a valid IPv4 address...", config->fas_remoteip);
			} else {
				debug(LOG_ERR, "fasremoteip - %s - is NOT a valid IPv4 address format...", config->fas_remoteip);
				debug(LOG_ERR, "Exiting...");
				exit(1);
			}
		} else {
			if (config->fas_port == 80) {
				debug(LOG_ERR, "Invalid fasport - port 80 is reserved and cannot be used for local FAS...");
				debug(LOG_ERR, "Exiting...");
				exit(1);
			}
		}

		if (config->fas_key && config->fas_secure_enabled == 1) {
			/* Check sha256sum command is available */
			if (execute_ret_url_encoded(msg, sizeof(msg) - 1, "printf 'test' | sha256sum") == 0) {
				safe_asprintf(&fashid, "sha256sum");
				debug(LOG_NOTICE, "sha256sum provider is available");
			} else {
				debug(LOG_ERR, "sha256sum provider not available - please install package to provide it");
				debug(LOG_ERR, "Exiting...");
				exit(1);
			}
			config->fas_hid = safe_strdup(fashid);
			free(fashid);
		}

		if (config->fas_key && config->fas_secure_enabled == 2) {
			/* PHP cli command can be php or php-cli depending on Linux version. */
			if (execute_ret(msg, sizeof(msg) - 1, "php -v") == 0) {
				safe_asprintf(&fasssl, "php");
				debug(LOG_NOTICE, "SSL Provider is active");
				debug(LOG_DEBUG, "SSL Provider: %s FAS key is: %s\n", &msg, config->fas_key);

			} else if (execute_ret(msg, sizeof(msg) - 1, "php-cli -v") == 0) {
				safe_asprintf(&fasssl, "php-cli");
				debug(LOG_NOTICE, "SSL Provider is active");
				debug(LOG_DEBUG, "SSL Provider: %s FAS key is: %s\n", &msg, config->fas_key);
			} else {
				debug(LOG_ERR, "PHP packages PHP CLI and PHP OpenSSL are required");
				debug(LOG_ERR, "Exiting...");
				exit(1);
			}
			config->fas_ssl = safe_strdup(fasssl);
			free(fasssl);
			safe_asprintf(&phpcmd,
				"echo '<?php "
				"if (!extension_loaded (openssl)) {exit(1);"
				"} ?>' | %s", config->fas_ssl);
			if (execute_ret(msg, sizeof(msg) - 1, phpcmd) == 0) {
				debug(LOG_NOTICE, "OpenSSL module is loaded\n");
			} else {
				debug(LOG_ERR, "OpenSSL PHP module is not loaded");
				debug(LOG_ERR, "Exiting...");
				exit(1);
			}
			free(phpcmd);
		}

		/* Make sure fas_remoteip is set. Note: This does not enable FAS. */
		if (!config->fas_remoteip) {
			config->fas_remoteip = safe_strdup(config->gw_ip);
		}

		if (config->fas_remotefqdn) {
			debug(LOG_NOTICE, "FAS FQDN is: %s\n", config->fas_remotefqdn);
		}

		debug(LOG_NOTICE, "Forwarding Authentication is Enabled.\n");

		if (config->fas_remotefqdn) {
			safe_asprintf(&fasurl, "http://%s:%u%s",
				config->fas_remotefqdn, config->fas_port, config->fas_path);
			config->fas_url = safe_strdup(fasurl);
		} else {
			safe_asprintf(&fasurl, "http://%s:%u%s",
				config->fas_remoteip, config->fas_port, config->fas_path);
			config->fas_url = safe_strdup(fasurl);
		}
		debug(LOG_NOTICE, "FAS URL is %s\n", config->fas_url);
		free(fasurl);

		if (config->fas_secure_enabled == 0) {
			debug(LOG_NOTICE, "Warning - Forwarding Authentication - Security is DISABLED.\n");
		}

		if (config->fas_secure_enabled == 2 && config->fas_key == NULL) {
			debug(LOG_ERR, "Error - faskey is not set - exiting...\n");
			exit(1);
		}
	}

	if (config->binauth) {
		debug(LOG_NOTICE, "Binauth is Enabled.\n");
		debug(LOG_NOTICE, "Binauth Script is %s\n", config->binauth);
	}

	/* Reset the firewall (cleans it, in case we are restarting after nodogsplash crash) */
	iptables_fw_destroy();

	/* Then initialize it */
	if (iptables_fw_init() != 0) {
		debug(LOG_ERR, "Error initializing firewall rules! Cleaning up");
		iptables_fw_destroy();
		debug(LOG_ERR, "Exiting because of error initializing firewall rules");
		exit(1);
	}

	/* Start client statistics and timeout clean-up thread */
	result = pthread_create(&tid_client_check, NULL, thread_client_timeout_check, NULL);
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create thread_client_timeout_check - exiting");
		termination_handler(0);
	}
	pthread_detach(tid_client_check);

	/* Start control thread */
	result = pthread_create(&tid, NULL, thread_ndsctl, (void *)(config->ndsctl_sock));
	if (result != 0) {
		debug(LOG_ERR, "FATAL: Failed to create thread_ndsctl - exiting");
		termination_handler(1);
	}

	result = pthread_join(tid, NULL);
	if (result) {
		debug(LOG_INFO, "Failed to wait for nodogsplash thread.");
	}
	MHD_stop_daemon(webserver);
	termination_handler(result);
}

/** Main entry point for nodogsplash.
 * Reads the configuration file and then starts the main loop.
 */
int main(int argc, char **argv)
{
	s_config *config = config_get_config();
	config_init();

	parse_commandline(argc, argv);

	/* Initialize the config */
	debug(LOG_INFO, "Reading and validating configuration file %s", config->configfile);
	config_read(config->configfile);
	config_validate();

	// Initializes the linked list of connected clients
	client_list_init();

	// Init the signals to catch chld/quit/etc
	debug(LOG_INFO, "Initializing signal handlers");
	init_signals();

	if (config->daemon) {

		debug(LOG_NOTICE, "Starting as daemon, forking to background");

		switch(safe_fork()) {
		case 0: // child
			setsid();
			main_loop();
			break;

		default: // parent
			exit(0);
			break;
		}
	} else {
		main_loop();
	}

	return 0; // never reached
}
