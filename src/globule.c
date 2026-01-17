/*
 * Reaver - Global variable access functions
 * Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL. *  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so. *  If you
 *  do not wish to do so, delete this exception statement from your
 *  version. *  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#include "globule.h"
#include "cracker.h"

struct globals *globule;

int globule_init()
{
	int ret = 0;

	globule = malloc(sizeof(struct globals));
	if(globule)
	{
		memset(globule, 0, sizeof(struct globals));
		ret = 1;
		globule->resend_timeout_usec = 200000;
		globule->output_fd = -1;

	}

	return ret;
}
void globule_deinit()
{
	int i = 0;

	if(globule)
	{
		for(i=0; i<P1_SIZE; i++)
                {
                        if(globule->p1[i]) free(globule->p1[i]);
                }
                for(i=0; i<P2_SIZE; i++)
                {
                        if(globule->p2[i]) free(globule->p2[i]);
                }

		if(globule->wps) wps_deinit(globule->wps);
		if(globule->handle) pcap_close(globule->handle);
		if(globule->pin) free(globule->pin);
		if(globule->iface) free(globule->iface);
		if(globule->ssid) free(globule->ssid);
		if(globule->session) free(globule->session);
		if(globule->static_p1) free(globule->static_p1);
		if(globule->static_p2) free(globule->static_p2);
		if(globule->fp) fclose(globule->fp);
		if(globule->exec_string) free(globule->exec_string);
		if(globule->htcaps) free(globule->htcaps);
		if(globule->ap_rates) free(globule->ap_rates);
		if(globule->ap_ext_rates) free(globule->ap_ext_rates);

		if(globule->output_fd != -1) close(globule->output_fd);

		free(globule);
	}
}

void set_log_file(FILE *fp)
{
	globule->fp = fp;
}
FILE *get_log_file(void)
{
	return globule->fp;
}

void set_last_wps_state(int state)
{
	globule->last_wps_state = state;
}
int get_last_wps_state()
{
	return globule->last_wps_state;
}

void set_session(char *value)  
{ 
	if(globule->session) free(globule->session);
	globule->session = (value) ? strdup(value) : NULL;
}
char *get_session()    
{
	return globule->session;  
} 

void set_p1_index(int index)
{
	if(index < P1_SIZE)
	{
		globule->p1_index = index;
	}
}
int get_p1_index()
{
	return globule->p1_index;
}

void set_p2_index(int index)
{
	if(index < P2_SIZE)
	{
		globule->p2_index = index;
	}
}
int get_p2_index()
{
	return globule->p2_index;
}

void set_p1(int index, char *value)
{
	if(index < P1_SIZE)
	{
		if(globule->p1[index]) free(globule->p1[index]);
		globule->p1[index] = (value) ? strdup(value) : NULL;
	}
}
char *get_p1(int index)
{
	if(index < P1_SIZE)
	{
		return globule->p1[index];
	}
	return NULL;
}

void set_p2(int index, char *value)
{
	if(index < P2_SIZE)
	{
		if(globule->p2[index]) free(globule->p2[index]);
		globule->p2[index] = (value) ? strdup(value) : NULL;
	}
}
char *get_p2(int index)
{
	if(index < P2_SIZE)
	{
		return globule->p2[index];
	}
	return NULL;
}

void set_key_status(enum key_state status)
{
	globule->key_status = status;
}
enum key_state get_key_status()
{
	return globule->key_status;
}

void set_delay(int delay)
{
	globule->delay = delay;
}
int get_delay()
{
	return globule->delay;
}

void set_fail_delay(int delay)
{
	globule->fail_delay = delay;
}
int get_fail_delay()
{
	return globule->fail_delay;
}

void set_validate_fcs(int validate)
{
	globule->validate_fcs = validate;
}
int get_validate_fcs(void)
{
	return globule->validate_fcs;
}

void set_recurring_delay(int delay)
{
	globule->recurring_delay = delay;
}
int get_recurring_delay()
{
	return globule->recurring_delay;
}

void set_recurring_delay_count(int value)
{
	globule->recurring_delay_count = value;
}
int get_recurring_delay_count()
{
	return globule->recurring_delay_count;
}

void set_lock_delay(int value)
{
	globule->lock_delay = value;
}
int get_lock_delay()
{
	return globule->lock_delay;
}

void set_ignore_locks(int value)
{
	globule->ignore_locks = value;
}
int get_ignore_locks()
{
	return globule->ignore_locks;
}

void set_eap_terminate(int value)
{
	globule->eap_terminate = value;
}
int get_eap_terminate()
{
	return globule->eap_terminate;
}

void set_max_pin_attempts(int value)
{
	globule->max_pin_attempts = value;
}
int get_max_pin_attempts()
{
	return globule->max_pin_attempts;
}

void set_max_num_probes(int value)
{
	globule->max_num_probes = value;
}
int get_max_num_probes()
{
	return globule->max_num_probes;
}

void set_rx_timeout(int value)
{
	globule->rx_timeout = value;
}
int get_rx_timeout()
{
	return globule->rx_timeout;
}

void set_timeout_is_nack(int value)
{
	globule->timeout_is_nack = value;
}
int get_timeout_is_nack()
{
	return globule->timeout_is_nack;
}

void set_m57_timeout(int value)
{
	globule->m57_timeout = value;
}
int get_m57_timeout()
{
	return globule->m57_timeout;
}

void set_out_of_time(int value)
{
	globule->out_of_time = value;
}
int get_out_of_time()
{
	return globule->out_of_time;
}

void set_debug(enum debug_level value)
{
	globule->debug = value;
	if(value == DEBUG) wpa_debug_level = MSG_DEBUG;
}
enum debug_level get_debug()
{
	return globule->debug;
}

void set_eapol_start_count(int value)
{
	globule->eapol_start_count = value;
}
int get_eapol_start_count()
{
	return globule->eapol_start_count;
}

void set_fixed_channel(int value)
{
	globule->fixed_channel = value;
}
int get_fixed_channel()
{
	return globule->fixed_channel;
}

void set_auto_channel_select(int value)
{
	globule->auto_channel_select = value;
}
int get_auto_channel_select()
{
	return globule->auto_channel_select;
}

void set_wifi_band(int value)
{
	globule->wifi_band = value;
}
int get_wifi_band()
{
	return globule->wifi_band;
}

void set_opcode(enum wsc_op_code value)
{
	globule->opcode = value;
}
enum wsc_op_code get_opcode()
{
	return globule->opcode;
}

void set_eap_id(uint8_t value)
{
	globule->eap_id = value;
}
uint8_t get_eap_id()
{
	return globule->eap_id;
}

void set_ap_capability(uint16_t value)
{
	globule->ap_capability = value;
}
uint16_t get_ap_capability()
{
	return globule->ap_capability;
}

void set_channel(int channel)
{
	globule->channel = channel;
}
int get_channel(void)
{
	return globule->channel;
}

void set_bssid(unsigned char *value)
{
	memcpy(globule->bssid, value, MAC_ADDR_LEN);
}
unsigned char *get_bssid()
{
	return globule->bssid;
}

void set_mac(unsigned char *value)
{
	memcpy(globule->mac, value, MAC_ADDR_LEN);
}
unsigned char *get_mac()
{
	return globule->mac;
}

void set_ssid(char *value)
{
	if(globule->ssid)
	{
		free(globule->ssid);
		globule->ssid = NULL;
	}

	if(value)
	{
		if(strlen(value) > 0)
		{
			globule->ssid = strdup(value);
		}
	}
}
char *get_ssid()
{
	return globule->ssid;
}

void set_iface(char *value)
{
	if(value)
	{
		if(globule->iface)
		{
			free(globule->iface);
		}

		globule->iface = strdup(value);
	}
	else if(globule->iface)
	{
		free(globule->iface);
		globule->iface = NULL;
	}
}
char *get_iface()
{
	return globule->iface;
}

void set_pin(char *value)
{
	if(globule->pin) free(globule->pin);
	globule->pin = (value) ? strdup(value) : NULL;
}
char *get_pin()
{
	return globule->pin;
}

void set_static_p1(char *value)
{
	if(globule->static_p1) free(globule->static_p1);
	globule->static_p1 = (value) ? strdup(value) : NULL;
}

char *get_static_p1(void)
{
	return globule->static_p1;
}

void set_static_p2(char *value)
{
	if(globule->static_p2) free(globule->static_p2);
	globule->static_p2 = (value) ? strdup(value) : NULL;
}

char *get_static_p2(void)
{
	return globule->static_p2;
}

void set_pin_string_mode(int value)
{
	globule->use_pin_string = value;
}

int get_pin_string_mode(void)
{
	return globule->use_pin_string;
}

void set_win7_compat(int value)
{
	globule->win7_compat = value;
}

int get_win7_compat(void)
{
	return globule->win7_compat;
}

void set_dh_small(int value)
{
	globule->dh_small = value;
}
int get_dh_small(void)
{
	return globule->dh_small;
}

void set_external_association(int value)
{
	globule->external_association = value;
}
int get_external_association(void)
{
	return globule->external_association;
}

void set_nack_reason(enum nack_code value)
{
	globule->nack_reason = value;
}
enum nack_code get_nack_reason()
{
	return globule->nack_reason;
}

void set_handle(pcap_t *value)
{
	globule->handle = value;
}
pcap_t *get_handle()
{
	return globule->handle;
}

void set_wps(struct wps_data *value)
{
	globule->wps = value;
}
struct wps_data *get_wps()
{
	return globule->wps;
}

void set_ap_htcaps(unsigned char *value, int len)
{
	if(globule->htcaps)
	{
		free(globule->htcaps);
		globule->htcaps = NULL;
		globule->htcaps_len = 0;
	}

	globule->htcaps = malloc(len);
	if(globule->htcaps)
	{
		memcpy(globule->htcaps, value, len);
		globule->htcaps_len = len;
	}
}

unsigned char *get_ap_htcaps(int *len)
{
	*len = globule->htcaps_len;
	return globule->htcaps;
}

void set_ap_rates(unsigned char *value, int len)
{
	if(globule->ap_rates)
	{
		free(globule->ap_rates);
		globule->ap_rates_len = 0;
	}

	globule->ap_rates = malloc(len);
	if(globule->ap_rates)
	{
		memcpy(globule->ap_rates, value, len);
		globule->ap_rates_len = len;
	}
}

unsigned char *get_ap_rates(int *len)
{
	*len = globule->ap_rates_len;
	return globule->ap_rates;
}

void set_ap_ext_rates(unsigned char *value, int len)
{
	if(globule->ap_ext_rates)
	{
		free(globule->ap_ext_rates);
		globule->ap_ext_rates_len = 0;
	}

	globule->ap_ext_rates = malloc(len);
	if(globule->ap_ext_rates)
	{
		memcpy(globule->ap_ext_rates, value, len);
		globule->ap_ext_rates_len = len;
	}
}

unsigned char *get_ap_ext_rates(int *len)
{
	*len = globule->ap_ext_rates_len;
	return globule->ap_ext_rates;
}

void set_exec_string(char *string)
{
	if(globule->exec_string)
	{
		free(globule->exec_string);
		globule->exec_string = NULL;
	}

	if(string)
	{
		globule->exec_string = strdup(string);
	}
}
char *get_exec_string(void)
{
	return globule->exec_string;
}

void set_oo_send_nack(int value)
{
	globule->oo_send_nack = value;
}
int get_oo_send_nack(void)
{
	return globule->oo_send_nack;
}

void set_mac_changer(int value)
{
	globule->mac_changer = value;
}
int get_mac_changer()
{
	return globule->mac_changer;
}

void set_vendor(int is_set, const unsigned char* v) {
	globule->vendor_oui[0] = is_set;
	if(is_set) memcpy(globule->vendor_oui+1, v, 3);
}
unsigned char *get_vendor(void) {
	if(!globule->vendor_oui[0]) return 0;
	return globule->vendor_oui+1;
}

void set_repeat_m6(int val) {
	globule->repeat_m6 = val;
}

int get_repeat_m6(void) {
	return globule->repeat_m6;
}

int get_output_fd(void) { return globule->output_fd; }

#include "pcapfile.h"
void set_output_fd(int fd) {
	globule->output_fd = fd;
	if (fd != -1) pcapfile_write_header(fd);
}

void set_follow_channel(int value)
{
	globule->follow_channel = value;
}
int get_follow_channel(void)
{
	return globule->follow_channel;
}

/* Adaptive delay and exponential backoff functions */
void set_adaptive_delay(int value)
{
	globule->adaptive_delay = value;
}
int get_adaptive_delay(void)
{
	return globule->adaptive_delay;
}

void set_consecutive_timeouts(int value)
{
	globule->consecutive_timeouts = value;
}
int get_consecutive_timeouts(void)
{
	return globule->consecutive_timeouts;
}
void increment_consecutive_timeouts(void)
{
	globule->consecutive_timeouts++;
}
void reset_consecutive_timeouts(void)
{
	globule->consecutive_timeouts = 0;
}

void set_consecutive_nacks(int value)
{
	globule->consecutive_nacks = value;
}
int get_consecutive_nacks(void)
{
	return globule->consecutive_nacks;
}
void increment_consecutive_nacks(void)
{
	globule->consecutive_nacks++;
}
void reset_consecutive_nacks(void)
{
	globule->consecutive_nacks = 0;
}

void set_base_lock_delay(int value)
{
	globule->base_lock_delay = value;
}
int get_base_lock_delay(void)
{
	return globule->base_lock_delay;
}

void set_current_lock_delay(int value)
{
	globule->current_lock_delay = value;
}
int get_current_lock_delay(void)
{
	return globule->current_lock_delay;
}

void set_max_backoff_factor(int value)
{
	globule->max_backoff_factor = value;
}
int get_max_backoff_factor(void)
{
	return globule->max_backoff_factor ? globule->max_backoff_factor : 8;
}

/*
 * Calculate exponential backoff delay based on consecutive failures.
 * Uses 2^n backoff with a maximum multiplier.
 */
int calculate_backoff_delay(void)
{
	int base = get_base_lock_delay();
	int failures = get_consecutive_timeouts() + get_consecutive_nacks();
	int max_factor = get_max_backoff_factor();
	int factor = 1;
	int i;

	if(base <= 0) base = DEFAULT_LOCK_DELAY;

	/* Calculate 2^failures, capped at max_factor */
	for(i = 0; i < failures && factor < max_factor; i++)
	{
		factor *= 2;
	}
	if(factor > max_factor) factor = max_factor;

	return base * factor;
}

/*
 * Reset all backoff counters and restore original lock delay
 */
void reset_backoff(void)
{
	reset_consecutive_timeouts();
	reset_consecutive_nacks();
	set_current_lock_delay(get_base_lock_delay());
}

/* Statistics and reporting functions */
void set_json_output(int value)
{
	globule->json_output = value;
}
int get_json_output(void)
{
	return globule->json_output;
}

void set_status_interval(int value)
{
	if(value > 0)
		globule->status_interval = value;
}
int get_status_interval(void)
{
	return globule->status_interval ? globule->status_interval : DISPLAY_PIN_COUNT;
}

void set_total_attempts(int value)
{
	globule->total_attempts = value;
}
int get_total_attempts(void)
{
	return globule->total_attempts;
}
void increment_total_attempts(void)
{
	globule->total_attempts++;
}

void set_successful_pins(int value)
{
	globule->successful_pins = value;
}
int get_successful_pins(void)
{
	return globule->successful_pins;
}
void increment_successful_pins(void)
{
	globule->successful_pins++;
}

void set_failed_attempts(int value)
{
	globule->failed_attempts = value;
}
int get_failed_attempts(void)
{
	return globule->failed_attempts;
}
void increment_failed_attempts(void)
{
	globule->failed_attempts++;
}

void set_lock_detections(int value)
{
	globule->lock_detections = value;
}
int get_lock_detections(void)
{
	return globule->lock_detections;
}
void increment_lock_detections(void)
{
	globule->lock_detections++;
}

void set_session_start(time_t value)
{
	globule->session_start = value;
}
time_t get_session_start(void)
{
	return globule->session_start;
}

/*
 * Record a PIN attempt time and update moving average
 */
void record_pin_time(double seconds)
{
	int i;
	double sum = 0;
	int count = 0;

	globule->last_pin_times[globule->pin_time_index] = seconds;
	globule->pin_time_index = (globule->pin_time_index + 1) % 10;

	/* Calculate moving average from available samples */
	for(i = 0; i < 10; i++)
	{
		if(globule->last_pin_times[i] > 0)
		{
			sum += globule->last_pin_times[i];
			count++;
		}
	}

	if(count > 0)
		globule->avg_pin_time = sum / count;
}

double get_avg_pin_time(void)
{
	return globule->avg_pin_time;
}

/*
 * Calculate estimated time remaining in seconds
 * Returns -1 if cannot be calculated
 */
int calculate_eta(void)
{
	int remaining_pins = 0;
	double avg = get_avg_pin_time();

	if(avg <= 0)
		return -1;

	if(get_key_status() == KEY1_WIP)
	{
		/* Still working on first half */
		remaining_pins = (P1_SIZE - get_p1_index()) + P2_SIZE;
	}
	else if(get_key_status() == KEY2_WIP)
	{
		/* Working on second half */
		remaining_pins = P2_SIZE - get_p2_index();
	}
	else
	{
		return 0; /* Done */
	}

	return (int)(remaining_pins * avg);
}

/*
 * Output status in JSON format
 */
void output_json_status(int pin_count, time_t start_time)
{
	time_t now = time(NULL);
	time_t elapsed = now - start_time;
	int eta = calculate_eta();
	float percentage = 0;
	int attempts = 0;

	if(get_key_status() == KEY1_WIP)
	{
		attempts = get_p1_index() + get_p2_index();
	}
	else if(get_key_status() == KEY2_WIP)
	{
		attempts = P1_SIZE + get_p2_index();
	}
	else if(get_key_status() == KEY_DONE)
	{
		attempts = P1_SIZE + P2_SIZE;
	}

	percentage = (float)(((float)attempts / (P1_SIZE + P2_SIZE)) * 100);

	fprintf(stderr, "{\"type\":\"status\","
		"\"progress\":%.2f,"
		"\"attempts\":%d,"
		"\"elapsed\":%ld,"
		"\"avg_time\":%.2f,"
		"\"eta\":%d,"
		"\"p1_index\":%d,"
		"\"p2_index\":%d,"
		"\"key_status\":%d,"
		"\"total_attempts\":%d,"
		"\"successful\":%d,"
		"\"failed\":%d,"
		"\"locks\":%d}\n",
		percentage,
		pin_count,
		(long)elapsed,
		get_avg_pin_time(),
		eta,
		get_p1_index(),
		get_p2_index(),
		get_key_status(),
		get_total_attempts(),
		get_successful_pins(),
		get_failed_attempts(),
		get_lock_detections());
}

/*
 * Output final result in JSON format
 */
void output_json_result(int success, time_t start_time, time_t end_time)
{
	struct wps_data *wps = get_wps();
	time_t elapsed = end_time - start_time;

	fprintf(stderr, "{\"type\":\"result\","
		"\"success\":%s,"
		"\"elapsed\":%ld,"
		"\"total_attempts\":%d,"
		"\"successful\":%d,"
		"\"failed\":%d,"
		"\"locks\":%d",
		success ? "true" : "false",
		(long)elapsed,
		get_total_attempts(),
		get_successful_pins(),
		get_failed_attempts(),
		get_lock_detections());

	if(success && get_pin())
	{
		fprintf(stderr, ",\"pin\":\"%s\"", get_pin());
		if(wps && wps->key)
			fprintf(stderr, ",\"psk\":\"%s\"", wps->key);
		if(wps && wps->essid)
			fprintf(stderr, ",\"essid\":\"%s\"", wps->essid);
	}

	fprintf(stderr, "}\n");
}
