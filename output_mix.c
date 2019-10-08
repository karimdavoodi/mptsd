/*
 * mptsd output mix packets
 * Copyright (C) 2010-2011 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "libfuncs/libfuncs.h"

#include "libtsfuncs/tsfuncs.h"

#include "data.h"
#include "config.h"
#include "input.h"

void output_show_programs(CONFIG *conf) {
	LNODE *lr, *lrtmp;
	list_for_each(conf->inputs, lr, lrtmp) {
		INPUT *r = lr->data;
		if (r->input_ready == 1) {
			//LOGf("OUTPUT: [%-12s] Service %d appeared.\n", r->channel->id, r->channel->service_id);
			r->input_ready++;
		}
	}
}

void * output_handle_mix(void *_config) {
	LNODE *lr, *lrtmp;
	LNODE *inpt; // Track last used input
	CONFIG *conf = _config;
	OUTPUT *o = conf->output;
	int buf_in_use = 0;
	unsigned int o_datasize, o_packets, packets;
	unsigned int o_maxpackets = o->obuf[0].size / TS_PACKET_SIZE;

	time_t  rep_time = 0;

	signal(SIGPIPE, SIG_IGN);

	/* KDKD increase priority */
	pthread_t thId = pthread_self();
	pthread_attr_t thAttr;
	int policy = 0;
	int max_prio_for_policy = 0;

	pthread_attr_init(&thAttr);
	pthread_attr_getschedpolicy(&thAttr, &policy);
	max_prio_for_policy = sched_get_priority_max(policy);
	pthread_setschedprio(thId, max_prio_for_policy);
	pthread_attr_destroy(&thAttr);
	//LOGf("pid=%ld pri = %d",thId,max_prio_for_policy);

	inpt = conf->inputs->tail; // Next is the first one
	while (!o->dienow) {
		OBUF *curbuf = &o->obuf[buf_in_use];

		usleep(o->obuf_ms - 0); /* KDKD 0->10 */ 

		output_show_programs(conf);

		while (curbuf->status != obuf_empty) {
			if (o->dienow)
				goto OUT;
			//LOGf("MIX: Waiting for obuf %d\n", buf_in_use);
			usleep(1);
		}

		list_lock(conf->inputs);

		o_datasize = o->psibuf->input - o->psibuf->output; // PSI data
		list_for_each(conf->inputs, lr, lrtmp) { // INPUT data
			INPUT *r = lr->data;
			o_datasize += r->buf->input - r->buf->output;
		}

		o_packets  = o_datasize / TS_PACKET_SIZE;
		packets = min(o_packets, o_maxpackets);

		/* KDKD  */
		long cur_time = time(NULL);
		if(((int)o_packets - (int)o_maxpackets)>1000 && (cur_time-rep_time)>60){
			LOGf("Overflow: Transponder %d (cur %d,max %d)\n",o->out_port-1200,
					(int)o_packets,(int)o_maxpackets);
			rep_time = cur_time;
			//file_write(conf,0);
		}
		double null_per_data = 1;
		double data_per_null = 0;
		if (o_maxpackets - packets) {
			data_per_null = (double)packets / (o_maxpackets-packets);
			if (data_per_null < 1) {
				null_per_data = (double)(o_maxpackets-packets) / packets;
				data_per_null = 1;
			}
		}

		curbuf->status = obuf_filling; // Mark buffer as being filled

		if (conf->debug) { //KDKD
			LOGf("MIX[%2d]: Data:%6u | Bufsz:%6d | Packs:%4u | D/N:%5.2f/%5.2f\n",
					buf_in_use,
					o_datasize,
					curbuf->size,
					packets,
					((double)packets / o_maxpackets) * 100,
					(double)100 - ((double)packets / o_maxpackets) * 100
				);
			LOGf("datapacks:%5d maxpacks:%5d null:%5d (%5.2f) | null_per_data:%5.2f data_per_null:%5.2f\n",
					packets,
					o_maxpackets,
					o_maxpackets-packets,
					100-((double)packets / o_maxpackets)*100,
					null_per_data,
					data_per_null
				);
		}

		unsigned int nulls=0, null_packets_count = o_maxpackets - packets;
		// The is no data in the input buffer, send only NULLs
		if (null_packets_count == o_maxpackets) {
			// Increase sended packets
			list_for_each(conf->inputs, lr, lrtmp) {
				INPUT *r = lr->data;
				r->outputed_packets += o_maxpackets;
			}
			goto NEXT_BUFFER;
		}

		unsigned int data_packets;
		int data_size;
		uint8_t *data;
		for (data_packets=0;data_packets<packets;data_packets++) {
			if (o->dienow)
				break;

			// Try the PSI data first
			data = cbuf_get(o->psibuf, TS_PACKET_SIZE, &data_size);
			if (data && data_size == TS_PACKET_SIZE){ 
				if (/*KDKD*/ data[0] == 0x47) 
					goto SEND_PACKET;
				else
					LOGf("Start !=  0x47");
			}

			// Loop over inputs
			int inputs_left = conf->inputs->items;  // Number of inputs
			while (inputs_left--) {
				inpt = inpt->next;
				INPUT *r = inpt->data;
				if (!r || !r->buf)
					continue;
				// Move pcrs || Move & rewrite prcs
				if (conf->pcr_mode == 1 || conf->pcr_mode == 3) {
					// Is there any data in this input?
					data = cbuf_peek(r->buf, TS_PACKET_SIZE, &data_size);
					if (data_size == TS_PACKET_SIZE) {
						uint16_t pid = ts_packet_get_pid(data);
						// Do we have PCR packet?
						if (pid == r->output_pcr_pid && ts_packet_has_pcr(data)) {
							if (r->output_pcr_packets_needed > 0 && r->outputed_packets < r->output_pcr_packets_needed) {
								data = NULL;
								data_size = 0;
								continue;
							}
							/*
							   LOGf("%10s | pcr:%15llu last_pcr:%15llu diff:%10lld packets:%5d needed_packs:%d diff:%d\n",
							   r->channel->id,
							   r->output_pcr,
							   r->output_last_pcr,
							   r->output_pcr - r->output_last_pcr,
							   r->outputed_packets,
							   r->output_pcr_packets_needed,
							   r->outputed_packets - r->output_pcr_packets_needed
							   );
							 */
							uint64_t last_last_pcr = r->output_last_pcr;
							r->output_last_pcr = r->output_pcr;
							r->output_pcr = ts_packet_get_pcr(data);
							if (last_last_pcr)
								r->output_pcr_packets_needed = round(conf->output_bitrate / 8 * 
										(r->output_pcr - r->output_last_pcr) / 27000000 / 188);
							/* 
							   KDKD why 27000000 ? 27MHZ program clock refrence for SD 
							 */
							r->outputed_packets = 0;
						}
						data = cbuf_get(r->buf, TS_PACKET_SIZE, &data_size);
						if (data_size == TS_PACKET_SIZE) // We have our data, no need to look at other inputs
							break;
					}
					// Do not move PCRs
				} else {
					data = cbuf_get(r->buf, TS_PACKET_SIZE, &data_size);
					if (data_size == TS_PACKET_SIZE){
						if(data[0]!=0x47)  // KDKD check data validity
							r->reconnect = 1;
						else break;

					} // We have our data, no need to look at other inputs
				}
			} // while (inputs_left--)

			// We have data. Mix it with NULLs and stuff it in the output buffer
			// If the have no data, the output buffer will automaticaly be left
			// with NULL packets
SEND_PACKET:
			if (data && data_size == TS_PACKET_SIZE) {

				// Mix data with NULLs
				if (nulls < null_packets_count) {
					if (round(nulls * data_per_null) < round(data_packets * null_per_data)) {
						nulls += round(data_packets * null_per_data) - round(nulls * data_per_null);
					}
					if (nulls > null_packets_count)
						nulls = null_packets_count;
				}
				if (data_packets+nulls >= o_maxpackets) { // Can't happen
					LOGf("wtf: %d packets:%d\n", data_packets+nulls, o_maxpackets);
					break;
				}
				/* KDKD remove null packet */ 
				//if(o->out_host.s_addr != 0x100007F ) /* send to net */
				//nulls = 0;
				uint8_t *bufptr = curbuf->buf + ((data_packets + nulls) * TS_PACKET_SIZE);
				memcpy(bufptr, data, TS_PACKET_SIZE);
			}

			// Increase sended packets
			list_for_each(conf->inputs, lr, lrtmp) {
				INPUT *r = lr->data;
				r->outputed_packets++;
			}
		}

NEXT_BUFFER:
		list_unlock(conf->inputs);
		curbuf->status = obuf_full; // Mark buffer as full

		buf_in_use = buf_in_use ? 0 : 1; // Switch buffer
	}

OUT:
	//LOG("OUTPUT: MIX thread stopped.\n");
	o->dienow++;

	LNODE *l, *tmp;
	list_for_each(conf->inputs, l, tmp) {
		INPUT *r = l->data;
		r->dienow = 1;
	}

	return 0;
}
