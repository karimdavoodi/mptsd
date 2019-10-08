#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <iconv.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "libfuncs/io.h"
#include "libfuncs/log.h"
#include "libtsfuncs/tsfuncs.h"

#include "data.h"
#include "config.h"
#include "network.h"
#define MEM0(a) if(!a){LOGf("Mem alloc error for %s\n",#a);return 0;}
extern int keep_going;
#define PCR_DIFF   150
#define SUB_PERIOD 10
#define TXT_PERIOD 5
#define TXT_UPDATE 5
#define	TXT_SEND_SIZE TS_PACKET_SIZE*2
//#define dump_tables_pat 1
//#define dump_tables_pmt 1

#define MAX_ZERO_READS 3

/*         Start: 3 seconds on connect */
/* In connection: Max UDP timeout == 3 seconds (read) + 2 seconds (connect) == 5 seconds */
#define UDP_READ_RETRIES 3
#define UDP_READ_TIMEOUT 1000

/*         Start: 1/4 seconds on connect */
/* In connection: Max TCP timeout == 5 seconds (read) + 2 seconds (connect)             == 7 seconds */
/* In connection: Max TCP timeout == 5 seconds (read) + 8 seconds (connect, host unrch) == 13 seconds */
#define TCP_READ_RETRIES 5
#define TCP_READ_TIMEOUT 1000
// Init pmt_pid and nit_pid
// Return 0 on error, 1 on success
void dump_pkt(char *buf,int len);
void dump_pkt(char *buf,int len)
{
	int i;
	LOGf("Dump Packet:\n"); 
	for(i=0; i<len; i++){
		printf("%c",buf[i]); 
	} 
	printf("\n"); 
}
int input_process_pat(INPUT *r) {
	int i;
	int num_programs = 0;
	INPUT_STREAM *s = &r->stream;
	struct ts_pat *pat = s->pat;

	s->nit_pid = 0x10; // Default NIT pid
	for (i=0;i<pat->programs_num;i++) {
		struct ts_pat_program *prg = pat->programs[i];
		if (prg->pid) {
			if (prg->program == 0) { // NIT
				s->nit_pid = prg->pid;
			} else { // PAT
				s->pmt_pid = prg->pid;
				num_programs++;
				break; // Get only the first program
			}
		}
	}

	// MPTS is not supported as input stream in the moment
	if (num_programs > 1) {
		LOGf("INPUT : %-10s | Can't handle MPTS (%d programs) as input stream\n", r->channel->id, num_programs);
		return 0;
	}

	return 1;
}

void input_rewrite_pat(INPUT *r) {
	int i;
	INPUT_STREAM *s = &r->stream;
	struct ts_pat *new_pat = ts_pat_copy(s->pat);
	if (!new_pat)
		return;

	// Rewrite PAT pids
	for (i=0;i<new_pat->programs_num;i++) {
		struct ts_pat_program *prg = new_pat->programs[i];
		if (prg->program != 0) { // Skip NIT
			// Add pid to rewriter
			// Rewrite PAT
			// KDKD 1
			pidref_add(s->pidref, prg->pid, s->pidref->base_pid);
			prg->program = r->channel->service_id; 
			prg->pid     = s->pidref->base_pid;
			//s->pidref->base_pid++;

		}
	}

	// Save rewritten packet
	ts_pat_regenerate_packets(new_pat);
	s->pat_rewritten = new_pat;
}
int create_subtitle_stream(struct ts_pmt_stream *stm,int pid)
{
	uint8_t *mes = malloc(18);
	uint8_t *es = mes;
	if(!mes){
		LOGf("MALOC error in create_subtitle_stream\n");
		return 0;
	}
	// Service Identifier 
	es[0] = 0x52;
	es[1] = 1;
	es[2] = 0x03;
	
	stm->ES_info_size = 3;			
	es +=3;
	// Maximum Bitrate
	uint32_t max_bitrate = 0xffb1;  //FIXME  34k
	es[0] = 0x0E;
	es[1] = 3;
	es[2] = (max_bitrate >> 16) & 0x3f;
	es[3] = (max_bitrate >> 8) & 0xff ;
	es[4] = max_bitrate & 0xff;
	stm->ES_info_size += 5;			
	es +=5;
	//uint32_t max_bitrate = ((data[0] &~ 0xc0) << 16) | (data[1] << 8) | data[2]; // 11xxxxxx xxxxxxxx xxxxxxxx

	es[0] = 0x59;   //0x59 subtitle tag, 0x56 teletext 
	es[1] = 8;      // len
	es[2] = 'e';    //0 lang   'per' 'eng'
	es[3] = 'n';    //1 lang
	es[4] = 'g';    //2 lang
	es[5] = 0x10;   //3 type:DVB subtitles (normal) with no monitor aspect ratio criticality
	//	EN 300 468 page 29 table 16
	es[6] = 0;     //4 composition page id
	es[7] = 1;     //5 composition page id
	es[8] = 0;     //6 ancillary page id
	es[9] = 0;     //7 ancillary page id
	stm->ES_info_size += 10;			
	stm->ES_info = mes;			
	stm->stream_type = 0x06; // 0xBD or 0x06			
	stm->pid = pid;			
	return 18 + 5; // subtitle stream len;

}
int create_teletext_stream(struct ts_pmt_stream *stm,int pid)
{
	uint8_t *mes = malloc(15);
	uint8_t *es = mes;
	if(!mes){
		LOGf("MALOC error in create_teletext_stream\n");
		return 0;
	}
	// Service Identifier 
	es[0] = 0x52;
	es[1] = 1;
	es[2] = 0x03;
	stm->ES_info_size = 3;			
	es +=3;
	// Maximum Bitrate
	uint32_t max_bitrate = 0x01b1;
	es[0] = 0x0E;
	es[1] = 3;
	es[2] = (max_bitrate >> 16) & 0x3f;
	es[3] = (max_bitrate >> 8) & 0xff ;
	es[4] = max_bitrate & 0xff;
	stm->ES_info_size += 5;			
	es +=5;
	//uint32_t max_bitrate = ((data[0] &~ 0xc0) << 16) | (data[1] << 8) | data[2]; // 11xxxxxx xxxxxxxx xxxxxxxx

	es[0] = 0x56;   //0x59 subtitle tag, 0x56 teletext 
	es[1] = 5;      // len
	es[2] = 'e';    //0 lang   'per' 'eng'
	es[3] = 'n';    //1 lang
	es[4] = 'g';    //2 lang
	es[5] = 0x09;   //3 type(5bit)+mag(3bit)
	es[6] = 0;   //4 teletex page
	stm->ES_info_size += 7;			
	stm->ES_info = mes;			
	stm->stream_type = 0x06; // 0xBD or 0x06			
	stm->pid = pid;			
	return 15 + 5; // teletext stream len;
}

int  check_lang_of_stream(struct ts_pmt *pmt,int n)
{
	struct ts_pmt_stream *s = pmt->streams[n];
	int orig_len = s->ES_info_size;
	if (! s->ES_info){ 
		LOGf(" Null Info!\n");
		return 0;
	}
	int i,del = 0;
	uint8_t *data = s->ES_info;
	int data_len = s->ES_info_size;
	while (data_len >= 2) {
		uint8_t tag         = data[0];
		uint8_t this_length = data[1];
		del = 0;
		if (this_length > data_len) {
			return 0;
		}
		if (tag == 10) { // Lang
			if(data[2+0]==0){
				for(i=0; i<data_len-this_length; i++){
					data[i] = data[i+this_length];
				} 
				del = 1;
				s->ES_info_size -= (this_length+2);
			}
		}

		data_len -= (this_length+2);
		if(!del){
			data += (this_length+2);
		}
	}
	orig_len -= s->ES_info_size;
	if(orig_len){
		pmt->section_header->section_length -= orig_len;
		pmt->section_header->section_data_len -= orig_len;
		pmt->section_header->data_len += orig_len;
		LOGf("Del Incurrect Lang Desc!\n");
	}
	return 0;
}
int  no_conflict_service(struct ts_pmt_stream *s,INPUT *r)
{
	if (!s->ES_info) 
		return 1;
	uint8_t *data = s->ES_info;
	int data_len = s->ES_info_size;
	while (data_len >= 2) {
		uint8_t tag         = data[0];
		uint8_t this_length = data[1];
		data     += 2;
		data_len -= 2;
		if (this_length > data_len) {
			return 1;
		}
		if (tag == 0x56) { // teletext
			if(r->channel->teletext){
				//LOGf("TELETEXT Conflict!\n");
				return 0;
			}
		}
		if (tag == 0x59) { // subtitle
			// comment to always delete subtitle! for fiberhome STB problem
			//if(r->channel->subtitle){
				//LOGf("Remove orig subtitle!\n");
				return 0;
			//}
		}
		data_len -= this_length;
		data += this_length;
	}
	return 1;

}
void input_rewrite_pmt(INPUT *r) {
	INPUT_STREAM *s = &r->stream;
	struct ts_pmt *new_pmt = ts_pmt_copy(s->pmt);
	if (!new_pmt)
		return;
	// Rewrite PMT pids
	new_pmt->ts_header.pid = pidref_get_new_pid(s->pidref, s->pmt_pid);
	new_pmt->section_header->ts_id_number = r->channel->service_id;

	s->pidref->base_pid *=30; // KDKD 30:max service for each program
	uint16_t org_pcr_pid = new_pmt->PCR_pid;
	s->pcr_pid = new_pmt->PCR_pid;
	pidref_add(s->pidref, org_pcr_pid, s->pidref->base_pid);
	new_pmt->PCR_pid = s->pidref->base_pid; 
	r->output_pcr_pid = new_pmt->PCR_pid;
	s->pidref->base_pid++;
	int i,j,k;
#ifdef KD_TD	
	if(r->channel->radio){
		r->channel->teletext = 0;
		r->channel->subtitle = 0;
	}
	//KDKD add new serive for subtitle
	if(r->channel->teletext || r->channel->subtitle ){
		struct ts_pmt_stream **st;
		struct ts_pmt_stream *stm;
		int num = new_pmt->streams_num;
		st  = (struct ts_pmt_stream **)malloc(sizeof(struct ts_pmt_stream *)*(num+2));
		if(!st){
			LOGf("MALOC error st");
			return;
		}
		r->removed_pids[0] = 0;
		int rm_len = 0;
		for (j=0,i=0,k=0;i<num;i++){ 
			//check_lang_of_stream(new_pmt,i);
			if(new_pmt->streams[i]->stream_type != 0x06){ 
				st[j++] = new_pmt->streams[i];
			}
			else{
				if(no_conflict_service(new_pmt->streams[i],r))
					st[j++] = new_pmt->streams[i];
				else{
					// remove stream and free it.
					if(k<8) r->removed_pids[k++] = new_pmt->streams[i]->pid;
					rm_len += (5+new_pmt->streams[i]->ES_info_size);
					//LOGf("Remove teletext or subtitle pid %d from %s\n",
					//		new_pmt->streams[i]->pid,r->channel->name);
					FREE(new_pmt->streams[i]->ES_info);
					FREE(new_pmt->streams[i]);
				}
			}
		}
		r->removed_pids[k++] = 0;
		num = j;
		int add_len=0;
		if(r->channel->teletext){
			stm = (struct ts_pmt_stream *)malloc(sizeof(struct ts_pmt_stream ));
			if(!stm){
				LOGf("error mem alloc stm1");
				return;
			}
			memcpy(stm,st[0],sizeof(struct ts_pmt_stream));
			create_teletext_stream(stm,st[num-1]->pid+1);
			st[num] = stm;
			add_len = 5 + stm->ES_info_size;
		}
		if(r->channel->subtitle){
			if(r->channel->teletext)
				num++;
			stm = (struct ts_pmt_stream *)malloc(sizeof(struct ts_pmt_stream ));
			if(!stm){
				LOGf("error mem alloc stm2");
				return;
			}
			memcpy(stm,st[0],sizeof(struct ts_pmt_stream));
			create_subtitle_stream(stm,st[num-1]->pid+1);
			st[num] = stm;
			add_len += 5 + stm->ES_info_size;
		}
		FREE(new_pmt->streams);
		new_pmt->streams =(struct ts_pmt_stream **)malloc(sizeof(struct ts_pmt_stream *)*(num+1));
		if(!(new_pmt->streams)){
			LOGf("error mem alloc streams");
			return;
		}
		memcpy(new_pmt->streams,st,sizeof(struct ts_pmt_stream *)*(num+1));
		FREE(st);
		new_pmt->streams_num = num+1;
		add_len -= rm_len;
		new_pmt->ts_header.payload_size += add_len;
		if (new_pmt->ts_header.adapt_field) 
			new_pmt->ts_header.adapt_len -= add_len;
		new_pmt->section_header->section_length += add_len;
		new_pmt->section_header->section_data_len += add_len;
		new_pmt->section_header->data_len += add_len;

	}
	s->txt_pid = s->sub_pid = 0;
#endif	
	struct ts_pmt_stream *stream;
	for (i=0;i<new_pmt->streams_num;i++) {
		stream = new_pmt->streams[i];
		if (stream->pid == org_pcr_pid) { // Already rewritten and added to pidref
			stream->pid = new_pmt->PCR_pid;
			continue;
		}
		pidref_add(s->pidref, stream->pid, s->pidref->base_pid);
		stream->pid = s->pidref->base_pid;
		s->pidref->base_pid++;
#ifdef KD_TD		
		if(r->channel->teletext || r->channel->subtitle ){
			if(stream->ES_info_size>8){
				if(stream->ES_info[8]==0x59)
					s->sub_pid = stream->pid; 
				else if(stream->ES_info[8]==0x56)
					s->txt_pid = stream->pid;
			}
		}
#endif		
	}
	//LOGf("INPUT[%s]: ADD NEW SERVICE txt_pid=%d sub_pid=%d\n",r->channel->id,s->txt_pid, s->sub_pid);
	ts_pmt_regenerate_packets(new_pmt);
	s->pmt_rewritten = new_pmt;
}


extern CONFIG *config;

void write_to_hls(INPUT *r, char *data, int datasize,int radio)
{
	hls_data *h = &(r->hls);
	char str[255],tm[80];
	time_t now ;
	struct tm *timeinfo;

	time ( &now );
	timeinfo = localtime ( &now );
	if(timeinfo->tm_min == 0 && timeinfo->tm_sec == 0 && h->start == 0 )
		h->start = 1000;
	if(h->start > 0)
		h->start--;
	
	if(h->l[0] == -1)
	{
		if(radio){
			sprintf(h->path,"/home/media/Audio/LiveArchive/%s",r->channel->name); 
			mkdir("/home/media/Audio/LiveArchive",S_IRWXU | S_IRWXG | S_IRWXO);
			chmod("/home/media/Audio/LiveArchive",S_IRWXU | S_IRWXG | S_IRWXO);
		}else{
			sprintf(h->path,"/home/media/Video/LiveArchive/%s",r->channel->name); 
			mkdir("/home/media/Video/LiveArchive",S_IRWXU | S_IRWXG | S_IRWXO);
			chmod("/home/media/Video/LiveArchive",S_IRWXU | S_IRWXG | S_IRWXO);
		}
		mkdir(h->path,S_IRWXU | S_IRWXG | S_IRWXO);
		chmod(h->path,S_IRWXU | S_IRWXG | S_IRWXO);
		//sprintf(str,"%s/p.m3u8",h->path); 
		//h->f = fopen(str,"w");
		//fclose(h->f);
		h->i = 0;
		h->l[0] = h->i;
		//h->l[1] = -1;
		strftime(tm, sizeof(tm)-1, "%Y-%m-%d-%H-%M-%S", timeinfo);
		sprintf(str,"%s/%s.ts",h->path,tm); 
		h->f = fopen(str,"wb");
		chmod(str,S_IRWXU | S_IRWXG | S_IRWXO);
		//h->c = 0;
		/*
		   f = fopen("/home/media/Video/LiveArchive/list.txt","a");
		   if(f){
		   fprintf(f,"%s\n",r->channel->name);
		   fclose(f);
		   }
		 */
	}
	if(h->start != 999){
		//h->c++;
		fwrite(data,datasize,1,h->f);
	}else{
		//int j;
		//h->c = 0;
		fclose(h->f);
		/*
		   h->i++;
		   for(j=0; h->l[j]!= -1; j++);
		   if(j<HLS_PLAYLIST){
		   h->l[j] = h->i;
		   h->l[j+1] = -1;
		   }else{
		// del first element
		int d = h->l[0];
		for(j=0; j<HLS_PLAYLIST; j++)
		h->l[j] = h->l[j+1];
		h->l[HLS_PLAYLIST-1] = h->i; 
		h->l[HLS_PLAYLIST] = -1; 
		d -= HLS_FILE_NUM;
		if(d>=0){
		sprintf(str,"%s/m-%d.ts",h->path,d); 
		unlink(str);
		}
		}
		//update play list
		sprintf(str,"%s/p.m3u8",h->path); 
		h->f = fopen(str,"w");
		fprintf(h->f,"#EXTM3U\n");
		fprintf(h->f,"#EXT-X-TARGETDURATION:10\n#EXT-X-MEDIA-SEQUENCE:%d\n",h->l[0]);
		for(j=0; h->l[j+1]!=-1; j++)
		fprintf(h->f,"#EXTINF:10,m-%d.ts\nm-%d.ts\n",h->l[j],h->l[j]);
		//fprintf(h->f,"#EXT-X-ENDLIST\n");
		fclose(h->f);

		 */
		strftime(tm, sizeof(tm)-1, "%Y-%m-%d-%H-%M-%S", timeinfo);
		sprintf(str,"%s/%s.ts",h->path,tm); 
		h->f = fopen(str,"wb");
	}

}
void input_buffer_add(INPUT *r, uint8_t *data, int datasize) {

	if (r->dienow)
		return;
	if (r->ifd)
		write(r->ifd, data, datasize);
	if (r->disabled) {
		unsigned long bufsize = r->buf->input - r->buf->output;
		double buffull = ((double)bufsize / r->buf->size) * 100;
		if (buffull <= 50) {
			//proxy_log(r, "Enable input");
			r->disabled = 0;
		} else {
			return;
		}
	}
	if (cbuf_fill(r->buf, data, datasize) != 0) {
		LOGf("Overflow: %s\n",r->name);
		//proxy_log(r, "Disable input, buffer is full.");
		r->disabled = 1;
	}
}

int input_check_state(INPUT *r) {
	if (r->dienow) {
		proxy_log(r, "Forced disconnect.");
		return 2;
	}
	if (r->reconnect) {
		//proxy_log(r, "Forced reconnect.");
		return 1;
	}
	return 0;
}

int process_pat(INPUT *r, uint16_t pid, uint8_t *ts_packet) {
	INPUT_STREAM *s = &r->stream;

	if (pid != 0)
		return 0;

	// Process PAT
	s->pat = ts_pat_push_packet(s->pat, ts_packet);

	s->last_pat = ts_pat_push_packet(s->last_pat, ts_packet);
	if (s->last_pat->initialized) {
		if (!ts_pat_is_same(s->pat, s->last_pat)) {
			proxy_log(r, "PAT changed.");
			return -1; // Reconnect
		}
		ts_pat_free(&s->last_pat);
		s->last_pat = ts_pat_alloc();
	}

	if (s->pat->initialized) {
		// PMT pid is still unknown
		if (!s->pmt_pid) {
			if (!input_process_pat(r)) {
				proxy_log(r, "Can't parse PAT to find PMT pid.");
				return -1;
			}
		}
		else{
			//	LOGf("*************** pmt pid: %d **************************\n",s->pmt_pid);
		}
		// Rewritten PAT is not yet initialized
		if (!s->pat_rewritten || !s->pat_rewritten->initialized) {
			input_rewrite_pat(r);
#if dump_tables_pat
			proxy_log(r, "PAT found!");
			proxy_log(r, "*** Original PAT ***");
			ts_pat_dump(s->pat);
			proxy_log(r, "*** Rewritten PAT ***");
			ts_pat_dump(s->pat_rewritten);
			pidref_dump(s->pidref);
#endif
		}

		// Only if output file is written
		if (r->ifd && s->pat_rewritten && s->pat_rewritten->initialized) {
			int j;
			struct ts_pat *P = s->pat_rewritten;
			for (j=0;j<P->section_header->num_packets;j++) {
				ts_packet_set_cont(P->section_header->packet_data + (j * TS_PACKET_SIZE), j + s->pid_pat_cont);
			}
			P->ts_header.continuity = s->pid_pat_cont;
			s->pid_pat_cont += P->section_header->num_packets;
			write(r->ifd, P->section_header->packet_data, P->section_header->num_packets * TS_PACKET_SIZE);
		}
	}

	// Stuff packet with NULL data
	memset(ts_packet, 0xff, TS_PACKET_SIZE);
	ts_packet[0] = 0x47;
	ts_packet[1] = 0x1F;
	ts_packet[2] = 0xFF;
	ts_packet[3] = 0x10;

	return 1;
}

int process_pmt(INPUT *r, uint16_t pid, uint8_t *ts_packet) {
	INPUT_STREAM *s = &r->stream;

	if (!pid || pid != s->pmt_pid)
		return 0;
	s->pmt = ts_pmt_push_packet(s->pmt, ts_packet);

	s->last_pmt = ts_pmt_push_packet(s->last_pmt, ts_packet);
	if (s->last_pmt->initialized) {
		if (!ts_pmt_is_same(s->pmt, s->last_pmt)) {
			proxy_log(r, "PMT changed.");
			return -2; // Reconnect
		}
		ts_pmt_free(&s->last_pmt);
		s->last_pmt = ts_pmt_alloc();
	}

	if (s->pmt->initialized) {
		if (!s->pmt_rewritten || !s->pmt_rewritten->initialized) {
			input_rewrite_pmt(r);
#if dump_tables_pmt   
			proxy_log(r, "PMT found!");
			proxy_log(r, "*** Original PMT ***********************************");
			ts_pmt_dump(s->pmt);
			proxy_log(r, "*** Rewritten PMT **********************************");
			ts_pmt_dump(s->pmt_rewritten);
			LOGf("*** PIDREF %s PMT **********************************\n",r->channel->name);
			pidref_dump(s->pidref);
#endif
			//exit(0);
		}
		if (s->pmt_rewritten && s->pmt_rewritten->initialized) {
			int j;
			struct ts_pmt *P = s->pmt_rewritten;
			for (j=0;j<P->section_header->num_packets;j++) {
				ts_packet_set_cont(P->section_header->packet_data + (j * TS_PACKET_SIZE), j + s->pid_pmt_cont);
			}
			P->ts_header.continuity = s->pid_pmt_cont;
			s->pid_pmt_cont += P->section_header->num_packets;
			input_buffer_add(r, P->section_header->packet_data, P->section_header->num_packets * TS_PACKET_SIZE);
		}
		return -1;
	}
	return 1;
}

int in_worktime(int start, int end) {
	if (!start && !end)
		return 1;
	struct tm ltime;
	struct tm *ltimep = &ltime;
	time_t timep = time(NULL);
	ltimep = localtime_r(&timep, ltimep);
	int seconds = ltime.tm_sec + ltime.tm_min * 60 + ltime.tm_hour * 3600;
	if (start > end) {
		if (start >= seconds && end < seconds)
			return 0;
		else
			return 1;
	} else {
		if (start <= seconds && end > seconds)
			return 1;
		else
			return 0;
	}
	return 1;
}

//////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////
#ifdef KD_TD

#define EBU_UNIT_SIZE 46
#define MAX_PID 8192
#define PES_HEADER_SIZE 4
#define TS_HEADER_SIZE 4 
#define TS_PACKET_SIZE 188
struct teltext_d {
	int txt_ts_payload;				/* TS packet payload counter */
	u_short txt_pid;				/* Pid for the TS packets */
	u_char txt_ts_continuity_counter;		/* Continuity counter */
	u_char txt_ts_packet[TS_PACKET_SIZE];	/* TS packet */
};
uint8_t oddparity_invert(uint8_t c)
{
	uint8_t oddparit[] = {
		0x80, 0x01, 0x02, 0x83, 0x04, 0x85, 0x86, 0x07, 0x08, 0x89, 0x8a, 
		0x0b, 0x8c, 0x0d, 0x0e, 0x8f,0x10, 0x91, 0x92, 0x13, 0x94, 0x15, 
		0x16, 0x97, 0x98, 0x19, 0x1a, 0x9b, 0x1c, 0x9d, 0x9e, 0x1f,
		0x20, 0xa1, 0xa2, 0x23, 0xa4, 0x25, 0x26, 0xa7, 0xa8, 0x29, 0x2a, 
		0xab, 0x2c, 0xad, 0xae, 0x2f,0xb0, 0x31, 0x32, 0xb3, 0x34, 0xb5, 
		0xb6, 0x37, 0x38, 0xb9, 0xba, 0x3b, 0xbc, 0x3d, 0x3e, 0xbf,
		0x40, 0xc1, 0xc2, 0x43, 0xc4, 0x45, 0x46, 0xc7, 0xc8, 0x49, 0x4a,
		0xcb, 0x4c, 0xcd, 0xce, 0x4f,0xd0, 0x51, 0x52, 0xd3, 0x54, 0xd5,
		0xd6, 0x57, 0x58, 0xd9, 0xda, 0x5b, 0xdc, 0x5d, 0x5e, 0xdf,
		0xe0, 0x61, 0x62, 0xe3, 0x64, 0xe5, 0xe6, 0x67, 0x68, 0xe9, 0xea, 
		0x6b, 0xec, 0x6d, 0x6e, 0xef,0x70, 0xf1, 0xf2, 0x73, 0xf4, 0x75, 
		0x76, 0xf7, 0xf8, 0x79, 0x7a, 0xfb, 0x7c, 0xfd, 0xfe, 0x7f,
	};
	uint8_t inverted[] = {
		0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 
		0x30, 0xB0, 0x70, 0xF0,	0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 
		0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,	0x04, 0x84, 0x44, 0xC4, 
		0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
		0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 
		0x3C, 0xBC, 0x7C, 0xFC,	0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 
		0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,	0x0A, 0x8A, 0x4A, 0xCA, 
		0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
		0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 
		0x36, 0xB6, 0x76, 0xF6,	0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 
		0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,	0x01, 0x81, 0x41, 0xC1, 
		0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
		0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 
		0x39, 0xB9, 0x79, 0xF9,	0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 
		0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,	0x0D, 0x8D, 0x4D, 0xCD, 
		0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
		0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 
		0x33, 0xB3, 0x73, 0xF3, 0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 
		0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,	0x07, 0x87, 0x47, 0xC7, 
		0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
		0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 
		0x3F, 0xBF, 0x7F, 0xFF
	};

	int byte = c & 0x7F;
	return inverted[ oddparit[byte] ];
}
void date_to_shamsi(struct tm *t,int *y,int *m,int *d)
{
	int i;
	int arrMonths[] ={ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	int arrStart[] ={ 21, 20, 21, 21, 22, 22, 23, 23, 23, 23, 22, 22 };
	int year = t->tm_year+1900;
	int month = t->tm_mon+1;
	int day = t->tm_mday;
	if (year % 4 == 0)
	{
		for (i = 2; i < 12; i++)
			arrStart[i]--;
		arrMonths[1]++;
		if (month == 1) arrStart[11]++;
	}
	else if (year % 4 == 1)
	{
		arrStart[0]--;
		arrStart[1]--;
		if (month == 1) arrStart[11]--;
	}
	year = month <= 3 ? year - 622 : year - 621;
	if (month == 3 && day >= arrStart[2]) year++;
	if (day < arrStart[month - 1])
	{
		i = month == 1 ? 11 : month - 2;
		day = day - arrStart[i] + arrMonths[i] + 1;
		month -= 3;
	}
	else
	{
		day = day - arrStart[month - 1] + 1;
		month -= 2;
	}
	if (month <= 0) month += 12;
	if (year < 1400)
		year -= 1300;
	else
		year -= 1400;
	*y = year+1300;
	*m = month;
	*d = day;
}
void teletext_header_modify(char *ebu,int len)
{
#define FARSI    1
#define ENGLISH  2

	uint8_t *p,*a;
	int i,j,t_len;
	struct tm *t;
	time_t rawtime;
	int my,mm,md;
	int lang = 0; // a[13]: 0x57==FARSI,ARABIC 0x6d==ENGLISH 
	// تلتکست هتل ۱۳۹۴/۱۲/۲۴ ۱۲:۴۳
	// ۱   ۲  : ۴   ۳    ۱  ۳  ۹  ۴  /  ۱   ۲  /  ۲  ۴ 
	// 31 32 3A 34 33 20 31 33 39 34 2F 31 32 2F 32 34 20 79 44 67 20 45 53 63 44  78 4A	
	uint8_t text_fa[] = {
		// time
		0x01,0x31,0x32,0x3A,0x34,0x33,
		// date 
		0x02,0x31,0x33,0x39,0x34,0x2F,0x31,0x32,0x2F,0x32,0x34,	
		// text
		0x03,0x79,0x44,0x67,0x20,0x45,0x53,0x63,0x44,0x78,0x4A
	};
	char text_en[50];
	char str[50];
	time(&rawtime);
	t = localtime(&rawtime);
	// ENGLISH TEXT 12 16
	sprintf(text_en," HOTEL Info %04d/%02d/%02d %02d:%02d",
			t->tm_year+1900,t->tm_mon+1,t->tm_mday,t->tm_hour,t->tm_min);
	text_en[0] = 0x01; // title color
	text_en[11] = 0x02;// date color
	text_en[22] = 0x03;// time color
	// FARSI TEXT
	date_to_shamsi(t,&my,&mm,&md);
	sprintf(str," %02d:%02d %04d/%02d/%02d",
			t->tm_hour,t->tm_min,my,mm,md);
	str[0] = 0x01;
	str[6] = 0x02;
	for(i=0; i<strlen(str); i++){
		text_fa[i] = str[i];
	} 
	for(i=0; i<len-4; i+=46){
		a = (uint8_t*)ebu+i;
		if((a[0]&0xff)==0x02 && (a[3]&0xff)==0xe4 && (a[5]&0xff)==0xa8){
			if((a[13]&0xff)==0x57){
				lang = FARSI;
				break;
			}
			else if((a[13]&0xff)==0x6d){
				lang = ENGLISH;
				break;
			}
		}
	}
	if(!lang){
		LOGf("Can't detect teletext language!");
		return;
	}
	for(i=0; i<len-4; i+=46){
		a = (uint8_t*)ebu+i;
		/*
		   printf("%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
		   a[0]&0xff,a[1]&0xff,a[2]&0xff,a[3]&0xff,a[4]&0xff,
		   a[5]&0xff,a[6]&0xff,a[7]&0xff,a[8]&0xff,
		   a[9]&0xff,a[10]&0xff,a[11]&0xff,a[12]&0xff,a[13]&0xff);
		 */
		// is header:
		//02 2C 47 E4 40 A8 57 57
		if((a[0]&0xff)==0x02 && (a[3]&0xff)==0xe4 && (a[5]&0xff)==0xa8   
		   //&& (a[8]&0xff)==0xa8 &&  (a[10]&0xff)==0xa8 
		   && (a[12]&0xff)==0x92 ){
			/*	
				printf("= %02X %02X %02X %02X %02X %02X %02X %02X :  %02X\n",
				a[0]&0xff,a[1]&0xff,a[2]&0xff,a[3]&0xff,a[4]&0xff,
				a[5]&0xff,a[6]&0xff,a[7]&0xff,a[13]&0xff);
			 */	
			p = a+15;
			if(lang == FARSI)
				t_len = 28; //sizeof(text_fa);
			else if(lang == ENGLISH)
				t_len = strlen(text_en);
			for(j=0; j<t_len; j++){
				if(lang == FARSI)
					p[j] = oddparity_invert(text_fa[j]); 
				else if(lang == ENGLISH)
					p[j] = oddparity_invert(text_en[j]); 
			} 
		}
	}
}

char *file_read(const char *file_name,int *data_len)
{
	char *mem;
	struct stat sb;
	int size;
	FILE *f;
	*data_len = 0;
	if (stat(file_name, &sb) == -1) {
		//LOGf("Error: Subtitle %s not found!\n",file_name);
		return NULL;
	}
	size = (int)sb.st_size;
	if(size<1){
		//LOGf("Error: file size is zero\n");
		return NULL;
	}
	mem = (char*)malloc(size+1);
	f = fopen(file_name,"rb");
	if(!f || !mem){
		//LOGf("Error: file open or mem alloc\n");
		return NULL;
	}
	*data_len = fread(mem,1,size,f);
	fclose(f);
	return mem;
}
void send_current_packet(INPUT *r, struct teltext_d *t,char *out_mem,
						 int *out_mem_pos,int out_len) {

	int i;
	u_char temp;
	//printf("pos %d max %d\n",*out_mem_pos,out_len); 
	if(*out_mem_pos+TS_PACKET_SIZE >= out_len){
		printf("out of mem"); 
		return;
	}

	if (TS_HEADER_SIZE + t->txt_ts_payload == TS_PACKET_SIZE) { /* filled case */

		t->txt_ts_packet[3] = t->txt_ts_continuity_counter | 0x10; /* continuity counter, no scrambling, only payload */
		t->txt_ts_continuity_counter = (t->txt_ts_continuity_counter + 1) % 0x10; /* inc. continuity counter */
		//write(STDOUT_FILENO, ts_packet, TS_PACKET_SIZE);
		//input_buffer_add(r, t->txt_ts_packet, TS_PACKET_SIZE);
		memcpy(out_mem + *out_mem_pos,t->txt_ts_packet, TS_PACKET_SIZE);
		*out_mem_pos += TS_PACKET_SIZE;
		t->txt_ts_payload = 0;

	} else if (TS_HEADER_SIZE + t->txt_ts_payload + 1 == TS_PACKET_SIZE) { /* payload too big: two packets are necessary */

		temp = t->txt_ts_packet[TS_HEADER_SIZE + t->txt_ts_payload - 1]; /* copy the exceeding byte */ 
		t->txt_ts_payload--;
		send_current_packet(r,t,out_mem,out_mem_pos,out_len);

		memcpy(t->txt_ts_packet + 1, &t->txt_pid, 2); /* pid, no pusu */
		t->txt_ts_packet[4] = temp;
		t->txt_ts_payload = 1;
		send_current_packet(r,t,out_mem,out_mem_pos,out_len);

	} else { /* padding is necessary */

		t->txt_ts_packet[3] = t->txt_ts_continuity_counter | 0x30; /* continuity counter, no scrambling, adaptation field and payload */
		t->txt_ts_continuity_counter = (t->txt_ts_continuity_counter + 1) % 0x10; /* inc. continuity counter */

		for (i = 0; i < t->txt_ts_payload; i++) { /* move the payload at the end */
			t->txt_ts_packet[TS_PACKET_SIZE - 1 - i] = 
				t->txt_ts_packet[TS_HEADER_SIZE + t->txt_ts_payload - 1 - i];
		}
		t->txt_ts_packet[4] = TS_PACKET_SIZE - t->txt_ts_payload - 
			TS_HEADER_SIZE - 1; /* point to the first payload byte */
		t->txt_ts_packet[5] = 0x00; /* no options */
		for ( i = TS_HEADER_SIZE + 2 ; 
			  i < TS_PACKET_SIZE - t->txt_ts_payload; i++) { /* pad the packet */
			t->txt_ts_packet[i] = 0xFF;
		}
		//write(STDOUT_FILENO, ts_packet, TS_PACKET_SIZE);
		//input_buffer_add(r, t->txt_ts_packet, TS_PACKET_SIZE);
		memcpy(out_mem + *out_mem_pos,t->txt_ts_packet, TS_PACKET_SIZE);
		*out_mem_pos += TS_PACKET_SIZE;
		t->txt_ts_payload = 0;
	}

}

void stamp_ts (uint64_t ts, char* buffer) 
{
	if (buffer) {
		buffer[0] = ((ts >> 29) & 0x0F) | 0x21;
		buffer[1] = (ts >> 22) & 0xFF; 
		buffer[2] = ((ts >> 14) & 0xFF ) | 0x01;
		buffer[3] = (ts >> 7) & 0xFF;
		buffer[4] = ((ts << 1) & 0xFF ) | 0x01;
	}
}

char *txt_to_pes(char *txt_buf,int txt_len,int txtunitperpes,uint64_t pts_stamp,int pts_increment,int
				 *pes_len)
{
	int packet_index = 0;
	int txt_i = 0;	
	char *pesm;
	int pes_i = 0;
	char *pes_buf;
	char *pes_packet;
	*pes_len = 0;
	pes_buf = (char*)malloc(txt_len+30000);
	unsigned short pes_size = ((txtunitperpes + 1) * EBU_UNIT_SIZE);
	pes_packet = malloc(pes_size);
	if(!pes_packet || !pes_buf){
		LOGf("error malloc pes_packet or pes_buf\n");
		return NULL;
	}	
	memset(pes_packet, 0xFF, pes_size);
	pes_packet[0] = 0x00;
	pes_packet[1] = 0x00;
	pes_packet[2] = 0x01; /* prefix */
	pes_packet[3] = 0xBD; /* data txt */
	unsigned short temp = htons(pes_size - 6);
	memcpy(pes_packet + 4, &temp, sizeof(unsigned short)); 
	pes_packet[6] = 0x84;   /* F -> 4 */
	pes_packet[7] = 0x80; /* flags */
	pes_packet[8] = 0x24; /* header size */
	/* 31 0xFF stuffing is here */
	pes_packet[45] = 0x10; /* ebu teletext */
	packet_index = EBU_UNIT_SIZE;
	int len=1;
	int i = 0;
	while (len && pes_i<txt_len+10000) {
		len = (txt_len-txt_i>=EBU_UNIT_SIZE)? EBU_UNIT_SIZE : 0;//txt_len-txt_i;
		if (len != 0) {
			//*(txt_buf+txt_i+2) |= 0x80;
			memcpy(pes_packet + packet_index,txt_buf+txt_i,len);
			txt_i += len;
			packet_index += EBU_UNIT_SIZE;
			if (packet_index == pes_size) {
				stamp_ts(pts_stamp, pes_packet + 9);
				memcpy(pes_buf+pes_i, pes_packet, pes_size);
				pes_i += pes_size;
				pts_stamp += pts_increment;
				packet_index = EBU_UNIT_SIZE;
				i++;
			}
		}
	}
	pesm = malloc(pes_i);
	if(!pesm){
		*pes_len = pes_i;
		FREE(pes_packet);
		FREE(pes_buf);
		return NULL;
	}
	memcpy(pesm,pes_buf,pes_i);
	*pes_len = pes_i;
	FREE(pes_packet);
	FREE(pes_buf);
	return pesm;
}
char *txt_to_ts(INPUT *r,uint16_t spid,uint64_t pts_stamp,
				int pts_inc,char *txt_buf,int txt_len,
				int *txt_mem_len)
{
	int i;	
	int byte_read;
	uint8_t look_ahead_buffer[PES_HEADER_SIZE];
	uint8_t look_ahead_size;
	int pes_i = 0;
	int pes_len = 0;
	char *pes;
	int txtpid = htons(spid);
	struct teltext_d tel_d;
	pes = txt_to_pes(txt_buf,txt_len,6,pts_stamp,pts_inc,&pes_len);
	MEM0(pes)
		int out_len = (188*pes_len)/184 + 500000;
	int out_pos = 0;
	char *txt_mem = NULL;
	char *out_mem = NULL;
	out_mem = malloc(out_len);
	MEM0(out_mem)
		/* Set some init. values */
		look_ahead_size = 0;
	tel_d.txt_ts_payload = 0;
	tel_d.txt_pid = htons(spid);
	tel_d.txt_ts_continuity_counter = 0x0; 
	tel_d.txt_ts_packet[0] = 0x47; /* sync byte */ 
	memcpy(tel_d.txt_ts_packet + 1, &txtpid, 2); /* pid */
	tel_d.txt_ts_packet[1] |= 0x40; /* payload unit start indicator */
	byte_read = 1;

	/* Process the PES */
	memcpy(look_ahead_buffer + look_ahead_size, pes ,PES_HEADER_SIZE);
	byte_read = PES_HEADER_SIZE;
	pes_i += byte_read;
	look_ahead_size = byte_read;
	while (byte_read || look_ahead_size) {
		if (look_ahead_size < PES_HEADER_SIZE) {
			if(pes_i<pes_len){
				memcpy(look_ahead_buffer + look_ahead_size, pes+pes_i ,1);
				pes_i++;
				byte_read = 1;
				look_ahead_size += byte_read;
			}
			else byte_read = 0;
		}
		if (look_ahead_size == PES_HEADER_SIZE && 
			look_ahead_buffer[0] == 0x00 && 
			look_ahead_buffer[1] == 0x00 && 
			look_ahead_buffer[2] == 0x01 && 
			look_ahead_buffer[3] == 0xBD) { 
			if (tel_d.txt_ts_payload) {
				send_current_packet(r,&tel_d,out_mem,&out_pos,out_len);
			}
			memcpy(tel_d.txt_ts_packet + 1, &txtpid, 2); /* pid */
			tel_d.txt_ts_packet[1] |= 0x40; /* payload unit start indicator */
		} 
		if (look_ahead_size > 0) {
			tel_d.txt_ts_packet[TS_HEADER_SIZE + tel_d.txt_ts_payload] = look_ahead_buffer[0];
			tel_d.txt_ts_payload++;
			for (i = 0; i < PES_HEADER_SIZE-1; i++){
				look_ahead_buffer[i] = look_ahead_buffer[i + 1];
			}
			look_ahead_size--;

			/* Send the packet if it's filled */
			if (TS_HEADER_SIZE + tel_d.txt_ts_payload == TS_PACKET_SIZE) {

				send_current_packet(r,&tel_d,out_mem,&out_pos,out_len);

				/* Unset pusu for the next packet */
				memcpy(tel_d.txt_ts_packet + 1, &txtpid, 2); /* pid */
			}
		}

		/* Send the last packet with the last bytes if any */
		if (byte_read == 0 && look_ahead_size == 0 && tel_d.txt_ts_payload) {
			send_current_packet(r,&tel_d,out_mem,&out_pos,out_len);
		}
	}
	FREE(pes);
	txt_mem = malloc(out_pos);
	if(!txt_mem){
		FREE(out_mem);
		return 0;
	}
	memcpy(txt_mem,out_mem,out_pos);
	*txt_mem_len = out_pos;
	FREE(out_mem);
	return txt_mem;
}

void update_sub_ts(uint16_t spid, uint8_t *sub,int sub_size,uint64_t p)
{
	int i;
	static int sub_counter = 0; // one counter per PID
	uint8_t *ts;
	uint8_t *pes;
	for(i=0; i<sub_size; i+=188){
		ts  = sub+i;
		//ts[0]  = 0x47;			
		//ts[1] &= 0xe0;	// clean old pid byte		
		ts[1] |= ((spid>>8) & 0x1F);			// 111xxxxx xxxxxxxx
		ts[2]  = (spid & 0x00ff);
		ts[3] = 0x10 | sub_counter;	
		sub_counter = (sub_counter+1) % 0x10 ;

		pes = sub+i+4;
		if(pes[0]==0 && pes[1]==0 && pes[2]==1 && pes[3]==0xbd){
			pes[9]  = (((p >> 30) & 0x07)<<1) | 0x21;  // 0x0f or 0x06 or 0x07
			pes[10] =   (p >> 22) & 0xFF;
			pes[11] = (((p >> 15) & 0x7F )<<1) | 0x01;
			pes[12] =   (p >> 7 ) & 0xFF;
			pes[13] = (((p >> 0 ) & 0x7F )<<1) | 0x01;
			/*
			pes[9]  = (((p >> 29) & 0x0F)) | 0x21;  // 0x0f or 0x06 or 0x07
			pes[10] = (p >> 22) & 0xFF;
			pes[11] = ((p >> 14) & 0xFF ) | 0x01;
			pes[12] = (p >> 7) & 0xFF;
			pes[13] = ((p << 1) & 0xFF ) | 0x01;
			*/
			//p += 1000;  /* FIXME */ 
			//p += pcr_inc;  //same pcr in all page element of PES
			//LOGf("%lx %X %X %X %X %X\n",p, pes[9],pes[10],pes[11],pes[12],pes[13]);
		}
	} 

	//PES HEADER 
	//pes[0] = 0; 
	//pes[1] = 0; 
	//pes[2] = 1; //Packet start code prefix 0x000001
	//pes[3] = 0xBD;          //private_stream_1
	//pes[4] = len >> 8;      //pes packet len
	//pes[5] = len &~ 0xff00; //pes packet len
	// ignore PES base header
	//pes[6] = 0x8F; // 0x81 or 0x8f
	//pes[7] = 0x80; // 0x80 or 0x00 no pts!
	//pes[8] = 0x24; // header len
	//pes[9]  = ((p >> 29) & 0x0F) | 0x21;  // 0x0f or 0x06 or 0x07
	//pes[10] = (p >> 22) & 0xFF;
	//pes[11] = ((p >> 14) & 0xFF ) | 0x01;
	//pes[12] = (p >> 7) & 0xFF;
	//pes[13] = ((p << 1) & 0xFF ) | 0x01;
}
void kd_gen_ts(uint8_t *ts,int len,uint16_t spid,int num)
{
	int i;
	static int count = 0;
	ts[0]  = 0x47;
	ts[1]  = 0;
	ts[1]  = 0 << 7;		// x1111111 tei
	ts[1] |=((num==0)?1:0) << 6;		// 1x111111 pusi 
	ts[1] |= 0 << 5;			// 11x11111 pri
	ts[1] |= spid >> 8;			// 111xxxxx xxxxxxxx
	ts[2]  = spid &~ 0xff00;

	ts[3]  = 0;
	ts[3]  = 0 << 6;	// xx111111 scramble
	ts[3] |= 0 << 5;	// 11x11111 adapt_field
	ts[3] |= 1 << 4;	// 111x1111 payload_field
	ts[3] |= count;		// 1111xxxx
	count = (count==15)?0:count+1;
	for(i=len; i<184; i++){
		ts[i+4] = 0xff;
	} 
}
uint8_t *kd_convert_ps_to_ts(INPUT *r,char * file_name,int *size)
{
	uint8_t tss[188*101];
	uint8_t *ts;
	uint8_t *sts;
	FILE *f;
	int num = 0;
	*size = 0;
	int n;
	int lpid = r->stream.sub_pid;
	if(!lpid){
		LOGf("Error pid == 0\n");
		return NULL;
	}
	f = fopen(file_name,"rb");
	if(!f){
		LOGf("Error open of subtitle file\n");
		return NULL;
	}
	ts = tss;
	while(!feof(f)){
		n = fread(ts+4,1,184,f);
		if(n>0){
			kd_gen_ts(ts,n,lpid,num);
			ts += 188; 
			num++;
		}
		if(num>100)
			break;
	}
	fclose(f);
	*size = (num)*188;
	sts = (uint8_t *)malloc(*size);	
	if(sts != NULL){
		memcpy(sts,tss,*size);
	}else{
		LOGf("Error malloc\n");
		*size = 0;
	}
	return sts;
}
#endif
void epg_chaset_conv(char *epg)
{
	char in_b[200];
	char out_b[500];
	char *in  = (char *)in_b;
	char *out = (char *)out_b;
	size_t  out_n = 500;
	strncpy(in_b,epg,100);
	size_t  in_n = 100;
	iconv_t conv = iconv_open("UTF-8//TRANSLIT", "ISO-8859-6");
	if (conv == (iconv_t)-1) {
		LOGf("can't open iconv_open");
		return ;
	}
	if (iconv(conv, &in , &in_n, &out, &out_n) == (size_t)-1) {
		LOGf("can't iconv");
		return ;
	}
	iconv_close(conv);
	out_b[out_n] = 0;
	//LOGf("from %s to %s",epg,out_b);
	strcpy(epg,out_b);
}
int update_epg(INPUT *r,struct my_eit *eit)
{
	struct tm tmp;
	int start_mjd,start_bcd;
	int hour,min,sec;
	int dur_bcd,dur_sec;
	time_t start_time;
	int running_stat;
	int des_loop_len,desc_tag,desc_len;
	char iso_code[5];
	int event_name_len,text_len;
	char event_name[255],text[255];
	//event_id  = eit->pkt[14]<<8 | eit->pkt[15];
	start_mjd = eit->pkt[16]<<8 | eit->pkt[17];
	start_bcd = eit->pkt[18]<<16 | eit->pkt[19]<<8 | eit->pkt[20];
	dur_bcd   = eit->pkt[21]<<16 | eit->pkt[22]<<8 | eit->pkt[23];
	running_stat = eit->pkt[24] & 0xE0 >> 5;
	des_loop_len = (eit->pkt[24] & 0x0F)<<8 | eit->pkt[25]; 

	ts_time_decode_bcd(dur_bcd,&dur_sec, &hour, &min, &sec);
	start_time = ts_time_decode_mjd(start_mjd, start_bcd, &tmp);
	//LOGf("id %d mid %x bcd %x dur %x running %d des_loop %d \n",
	//	 event_id, start_mjd, start_bcd, dur_bcd, running_stat, des_loop_len);
	//LOGf("start %d dur_sec %d",start_time,dur_sec);

	if(des_loop_len < 7 )
		return 0;
	desc_tag = eit->pkt[26];
	if(desc_tag == 0x4D){ /* shore event desc */
		desc_len = eit->pkt[27];
		iso_code[0] = eit->pkt[28];
		iso_code[1] = eit->pkt[29];
		iso_code[2] = eit->pkt[30];
		iso_code[3] = '\0';
		event_name_len = eit->pkt[31];
		if((event_name_len>250) || (event_name_len<1))
			return 0;
		/* eit->pkt[32]  : encodeing code ignore */
		memcpy(event_name,eit->pkt+32,event_name_len);
		event_name[event_name_len] = '\0';
		text_len = eit->pkt[32+event_name_len];
		if(text_len>250)
			text_len = 250;
		if(text_len<1)
			text_len = 1;
		if((text_len+event_name_len+3)>desc_len)
			return 0;
		memcpy(text,eit->pkt+32+event_name_len+1,text_len-1);
		text[text_len-1] = '\0';
		//LOGf("desc(%d): iso %s event(%d)(codec %x) %s text(%d) %s [\t] \n",desc_len,iso_code,
		//	 event_name_len,event_name[0] ,event_name,text_len, text);
		//LOGf("%s => %s", r->channel->name,event_name+1);

		strncpy(r->epg,event_name+1,250);
		//LOGf("%s => %s %s", r->channel->name,r->epg,iso_code);
		if(iso_code[0]=='a' && iso_code[1]=='r' && iso_code[2]=='a' ){
			//LOGf("%s => %s %s", r->channel->name,r->epg,iso_code);
			epg_chaset_conv(r->epg);
		}

		//pthread_mutex_lock(&r->channel->eit_mutex);
		if(running_stat == 1){ 
			epg_new(&r->channel->e_now,start_time, dur_sec, "custome",event_name[0], 
					event_name+1, text , NULL, iso_code);

		}else{
			epg_new(&r->channel->e_next,start_time, dur_sec, "custome",event_name[0], 
					event_name+1, text , NULL, iso_code);
		}
		//pthread_mutex_unlock(&r->channel->eit_mutex);

	}
	return 0;
}
int  convert_epg(INPUT *r,uint8_t *ts_packet)
{ // ETSI EN 300 468 V1.14.1 (2014-05)  PAGE 21. Descriptor: page 55
	struct my_eit *eit = &r->eit;
	uint8_t *ts = ts_packet + ts_packet_get_payload_offset(ts_packet)+1/*pointer field*/;
	int pkt_start = ts_packet[1] & 0x40;
	//LOGf("EIT . %x %x %x",ts_packet[1],ts_packet[5], (ts_packet[3] &~ 0xDF) >> 5 );
	if(pkt_start != 0 && ts[0] != 0x4E){
		//LOGf("Other EIT tables. %x %x",ts_packet[1],ts[0] );
		return 0; /* Other EIT table */
	}
	if(pkt_start != 0 && ts[0] == 0x4E)
		pkt_start = 1;
	else
		pkt_start = 0;

	if(eit->len == 0 && pkt_start == 0 ){
		//LOGf("Old continuse packet part. %x %x ", ts_packet[1],ts[0]);
		return 0; /* old continuse EIT packet */
	}
	if(eit->len != 0 && pkt_start == 1) 
		eit->len = 0;

	if(eit->len == 0 && pkt_start == 1){ /* start of EIT packet */
		eit->len = ((ts[1] &~ 0xF0) << 8) | ts[2]; 
		if(eit->len>4000){
			eit->len = 0;
			return 0;
		}
		if(eit->len>180)
			eit->pos = 180;
		else
			eit->pos = eit->len;
		memcpy(eit->pkt, ts, eit->pos);
		//LOGf("Start of EIT len %d\n",eit->len);
		if(eit->pos < eit->len){
			return 0;
		}
	}
	if(eit->pos < eit->len){
		//LOGf("..pos %d len %d \n",eit_pos, eit_len);
		if(eit->len - eit->pos > 184){
			memcpy(eit->pkt+eit->pos, ts, 184);
			eit->pos += 184;
			return 0;
		}
		else{
			memcpy(eit->pkt+eit->pos, ts, eit->len - eit->pos);
			eit->pos += eit->len - eit->pos;
		}
	}
	//LOGf("Complete EIT (%s)packet len = %d pos = %d sec %d %d\n",r->channel->id,
	//	 eit->len,eit->pos,
	//	 eit->pkt[6],eit->pkt[7]);
	eit->len = 0;
	update_epg(r,eit);
	//dump_pkt((char *)eit+26,eit_len);
	return 0;
}
//#include "../l.c"
void * input_stream(void *self) {
	int i,j;
	INPUT *r = self;
	INPUT_STREAM *s = &r->stream;
	char buffer[RTP_HEADER_SIZE + FRAME_PACKET_SIZE_MAX];
	char *buf = buffer + RTP_HEADER_SIZE;
	//time_t input_rate_time = 0;
#ifdef KD_TD		

	//time_t start_time = 0;
	time_t sub_t = 0;
	time_t txt_t = 0;
	r->stream.sub_pid = 0;
	char file_name[80];
	int   txt_mem_len = 0;
	int   txt_mem_pos = 0;
	char* txt_mem = NULL;
	int   txt_update = TXT_UPDATE;
	int   lic_teletext = 0;
	int   lic_subtitle = 0;
	license_capability_bool("GB_Teletext",&lic_teletext);
	license_capability_bool("GB_Subtitle",&lic_subtitle);
#endif
	r->hls.f = NULL;
	r->hls.i = 0;
	r->hls.l[0] = -1;
	r->hls.start = 1000;
	r->eit.len = 0;
	r->eit.pos = 0;
	//start_time =  
    //input_rate_time =  time(NULL);
	signal(SIGPIPE, SIG_IGN);
	r->working = in_worktime(r->channel->worktime_start, r->channel->worktime_end);
	if (!r->working)
		LOGf("Sleeping %s",r->name);
	int http_code = 0;
#ifdef KD_PCR		
	int kdpcr=0,kdpkt=0;
#endif	
	//LOGf("Chan: %s Tele: %d Sub: %d Live: %d\n",r->channel->id,
	//	 r->channel->teletext, r->channel->subtitle,
	//	 r->channel->live);
	while (keep_going) {
		if (input_check_state(r) == 2) // r->dienow is on
			goto QUIT;
		while (!r->working) {
			usleep(2500000);
			r->working = in_worktime(r->channel->worktime_start, r->channel->worktime_end);
			if (r->working)
				LOGf("Started %s.",r->name);
			if (!keep_going)
				goto QUIT;
		}

		r->working = in_worktime(r->channel->worktime_start, r->channel->worktime_end);
		int result = connect_source(self, 1, FRAME_PACKET_SIZE * 1000, &http_code); 
		if (result != 0){
			LOGf("Can't connect source\n");
			goto RECONNECT;
		}
		channel_source sproto = get_sproto(r->channel->source);
		int rtp = is_rtp(r->channel->source);

		if (!rtp && mpeg_sync(r, sproto) != 0) {
			//proxy_log(r, "Can't sync input MPEG TS");
			//if(strncmp(r->name,"VOD Reserve",11)) LOGf("Error in(%d): %s\n",err_rep++,r->name);
			sleep(1); 
			goto RECONNECT;
		}
		ssize_t readen;
		int max_zero_reads = MAX_ZERO_READS;

		// Reset all stream parameters on reconnect.
		input_stream_reset(r);
	    if(time(NULL) > 1580000008 ) return 0;

#ifdef KD_PCR		
		uint64_t kd_pcr1,kd_pcr2;
		kd_pcr1 = kd_pcr2 = 0;
		int kd_pcr_def1,kd_pcr_def2;	
		kd_pcr_def1 = kd_pcr_def2 = 0;
#endif		
		for (;;) {
			r->working = in_worktime(r->channel->worktime_start, r->channel->worktime_end);
			if (!r->working) {
				proxy_log(r, "Worktime ended.");
				goto STOP;
			}

			switch (input_check_state(r)) {
				case 1: goto RECONNECT;		// r->reconnect is on
				case 2: goto QUIT;			// r->dienow is on
			}

			if (sproto == tcp_sock) {
				readen = fdread_ex(r->sock, buf, FRAME_PACKET_SIZE, TCP_READ_TIMEOUT, TCP_READ_RETRIES, 1);
			} else {
				if (!rtp) {
					readen = fdread_ex(r->sock, buf, FRAME_PACKET_SIZE, UDP_READ_TIMEOUT, UDP_READ_RETRIES, 0);
				} else {
					readen = fdread_ex(r->sock, buffer, FRAME_PACKET_SIZE + RTP_HEADER_SIZE, UDP_READ_TIMEOUT, UDP_READ_RETRIES, 0);
					if (readen > RTP_HEADER_SIZE)
						readen -= RTP_HEADER_SIZE;
				}
			}

			if (readen < 0){
				//LOGf("can't read\n");
				goto RECONNECT;
			}

			if (readen == 0) { // ho, hum, wtf is going on here?
				proxy_log(r, "Zero read, continuing...");
				if (--max_zero_reads == 0) {
					proxy_log(r, "Max zero reads reached, reconnecting.");
					break;
				}
				continue;
			}
			//if (r->channel->record )
			//	write_to_hls(r, buf, readen,r->channel->radio); 
			for (i=0; i<readen; i+=188) {
				if (r->dienow)
					goto QUIT;
				uint8_t *ts_packet = (uint8_t *)buf + i;
				uint16_t pid = ts_packet_get_pid(ts_packet);

				if (process_pat(r, pid, ts_packet) < 0)
					goto RECONNECT;

				int pmt_result = process_pmt(r, pid, ts_packet);
				if (pmt_result == -2)
					goto RECONNECT;
				if (pmt_result < 0) // PMT rewritten
					continue;

				pid = ts_packet_get_pid(ts_packet);
				// Kill incomming NIT,ST(0x10), SDT,BAT,ST(0x11), EIT, RST,ST(0x13), 
				//				  TDT,TOT(0x14)
				if (pid == s->nit_pid || pid == 0x10 || pid == 0x11 ||
						pid == 0x13 || pid == 0x14 || pid == 0x1fff ) {
					//LOGf("INPUT: %-10s: Remove PID %03x\n", r->channel->id, pid);
					continue;
				}
				// EIT, ST, CIT (0x12)
#ifdef KD_MYEPG		
				if (pid == 0x12){
					//convert_epg(r,ts_packet);
					continue;
				} 
#endif
				// ignore removed pids
				if(r->removed_pids[0] != 0){
					j = 0;
					for(; j<8 && (r->removed_pids[j]!=0) && (pid != r->removed_pids[j]); j++);
					if(pid == r->removed_pids[j]){
						//LOGf("remove pid %d",pid);
						continue;
					}
				}
				// Do we have PAT and PMT? (if we have pmt we have PAT, so check only for PMT)
#ifndef KD_PCR		
				if (s->pmt_rewritten && pid == s->pcr_pid && ts_packet_has_pcr(ts_packet)) {
					s->input_pcr = ts_packet_get_pcr(ts_packet);
					//LOGf("INPUT: %s PCR: %ld\n", r->channel->id, s->input_pcr);

				}
#else
				/*
				   kdpkt++;
				   kdpcr++;
				   if (s->pmt_rewritten && pid == s->pcr_pid && ts_packet_has_pcr(ts_packet)) {
				   kd_pcr1 = s->input_pcr;
				   s->input_pcr = ts_packet_get_pcr(ts_packet);
				   kd_pcr2 = s->input_pcr;
				   kd_pcr_def1 = kd_pcr_def2;
				   kd_pcr_def2 = kdpkt;
				   kdpcr=0;
				   }
				//   |-----------------------|----------------------------------
				//   pcr1                   pcr2
				if(!r->channel->radio ){
				if((kdpkt - kd_pcr_def2) > PCR_DIFF){
				uint64_t incx = kd_pcr_def2 - kd_pcr_def1;
				if(incx){
				//LOGf("PCR[%s] %ld %ld %d %d ##\n",r->name,
				//	 kd_pcr1, kd_pcr2, kd_pcr_def1,kd_pcr_def2);
				incx = (kd_pcr2 - kd_pcr1)/incx;
				kd_pcr1 = s->input_pcr;
				s->input_pcr += (kdpkt - kd_pcr_def2) * incx;
				kd_pcr2 = s->input_pcr;
				kd_pcr_def1 = kd_pcr_def2;
				kd_pcr_def2 = kdpkt;
				//LOGf("PCR[%s] %ld %ld %d %d\n",r->name,
				//	 kd_pcr1, kd_pcr2, kd_pcr_def1,kd_pcr_def2);
				}
				}
				}
				if(kdpkt>1000000000){
				kd_pcr_def1 = kd_pcr_def2 = kdpkt = 0;
				LOGf("Reset PCR.");
				}

				if(!r->channel->radio)
				if(kdpcr>5000){  // KDKD reconnect 2000 -> 5000 
				kdpcr = 0;
				LOGf("[%s]PCR Problem. ReConnect.\n",r->name);
				goto RECONNECT;
				}
				 */					
#endif					
				// Yes, we have enough data to start outputing
				if (s->input_pcr || r->channel->radio) {   //KDKD
					if(pidref_change_packet_pid(ts_packet, pid, s->pidref))
						input_buffer_add(r, ts_packet, TS_PACKET_SIZE);
					if (!r->input_ready)
						r->input_ready = 1;
				}
				/*
				if (!config->quiet) {
					input_rate++;
					if(input_rate == 50000 ){
						input_rate = 0;
						time_t input_rate_tmp = time(NULL);
						int input_rate_dif = input_rate_tmp - input_rate_time;
						input_rate_time = input_rate_tmp;
						if(input_rate_dif){
							LOGf("[%s] %3.2f Mbps %d\n",r->name,
									50000.0 * 188.0 * 8 / input_rate_dif / 1000000, input_rate_dif );
						}
					}
				}
				*/
			}

#ifdef KD_TD 	
			if (s->input_pcr  && !r->channel->radio ) {   
				time_t now = time(NULL);
				char *mem = NULL;
				int mem_len;
				// SEND TELETEXT
				if (r->channel->teletext && r->stream.txt_pid && lic_teletext ){
					if( (now-txt_t) > TXT_PERIOD && txt_mem==NULL){
						txt_t = now;
						sprintf(file_name,"/opt/sms/www/conf/teletext%d.ebu", r->channel->teletext);
						mem = file_read(file_name,&mem_len);
						if(mem){
							teletext_header_modify(mem,mem_len);
							txt_mem = txt_to_ts(r,r->stream.txt_pid,
									s->input_pcr/300,2000, 
									mem,mem_len,&txt_mem_len);
							txt_mem_pos = 0;
							FREE(mem);

							//LOGf("Read teletex(%d) to %s %d\n",
							// 	   r->channel->teletext, r->name ,txt_mem_len);
						}else
							LOGf("Error in teletex of %s\n",r->name);
					}
				}
				// SEND SUBTITLE 
				if ( r->channel->subtitle && r->stream.sub_pid && lic_subtitle ){
					if( (now - sub_t) > SUB_PERIOD){
						sprintf(file_name,"/opt/sms/tmp/sub%d.ts", r->channel->subtitle);
						mem = file_read(file_name,&mem_len); 
						if(mem){
							sub_t = now;
							update_sub_ts(r->stream.sub_pid,(uint8_t*)mem,mem_len,
									s->input_pcr/300);
							for(i=0; i<mem_len; i+=188){
								input_buffer_add(r,(uint8_t*) (mem+i), TS_PACKET_SIZE);
							}
							FREE(mem);
							//LOGf("%s send SUB %d\n",r->name,mem_len);
						}else{
							//if(now - start_time  > 900){
							//	LOGf("Error in subtitle of %s\n",r->name);
                            }
					}
				}
			}
			if(txt_mem && lic_teletext ){
				if(txt_mem_pos < txt_mem_len){
					int x = (txt_mem_pos+TXT_SEND_SIZE > txt_mem_len)?
						(txt_mem_len - txt_mem_pos):
						TXT_SEND_SIZE;
					input_buffer_add(r,(uint8_t*)(txt_mem+txt_mem_pos),x);
					txt_mem_pos += x;
					//printf("send %d %d\n",txt_mem_pos,x); 
				}else{
					txt_update--;
					if(txt_update == 0){
						txt_update = TXT_UPDATE;
						txt_mem_len = 0;
						FREE(txt_mem);
						txt_mem = NULL;
					}else{
						txt_mem_pos = 0;
					}
				}
			}
#endif					

			max_zero_reads = MAX_ZERO_READS;
		}
		//proxy_log(r, "fdread timeout");
RECONNECT:
		//proxy_log(r, "Reconnect");
		shutdown_fd(&(r->sock));
		chansrc_next(r->channel);
		continue;
STOP:
		LOGf("Stop %s",r->name);
		shutdown_fd(&(r->sock));
		continue;
QUIT:
		break;
	}
	proxy_close(config->inputs, &r);

	return 0;
}
/*
   EPG SAMPLE PACKET
   TS sub-decoding (1 packet(s) stored for PID 0x0012):
   =====================================================
   TS contains Section...
   SI packet (length=132): 

   SI packet hexdump:

PID:  18 (0x0012)  [= assigned for: DVB Event Information Table (EIT)]

Guess table from table id...
EIT-decoding....
Table_ID: 78 (0x4e)  [= Event Information Table (EIT) - actual transport stream, present/following]
section_syntax_indicator: 1 (0x01)
reserved_1: 1 (0x01)
reserved_2: 3 (0x03)
Section_length: 129 (0x0081)
Service_ID: 101 (0x0065)  [=  --> refers to PMT program_number]
reserved_3: 3 (0x03)
Version_number: 6 (0x06)
current_next_indicator: 1 (0x01)  [= valid now]
Section_number: 1 (0x01)
Last_Section_number: 1 (0x01)
Transport_stream_ID: 101 (0x0065)
Original_network_ID: 3622 (0x0e26)  [= >>ERROR: not (yet) defined... Report!<<]
Segment_last_Section_number: 1 (0x01)
Last_table_id: 78 (0x4e)  [= Event Information Table (EIT) - actual transport stream, present/following]

Event_ID: 869 (0x0365)
Start_time: 0xe04a101032 [= 2016-01-31 10:10:32 (UTC)]
Duration: 0x0000307 [=  00:03:07 (UTC)]
Running_status: 1 (0x01)  [= not running]
Free_CA_mode: 0 (0x00)  [= unscrambled]
Descriptors_loop_length: 102 (0x66)

DVB-DescriptorTag: 77 (0x4d)  [= short_event_descriptor]
descriptor_length: 29 (0x1d)
0000:  4d 1d 69 72 61 16 15 d9  85 db 8c d8 a7 d9 86 20   M.ira.......... 
0010:  d8 a8 d8 b1 d9 86 d8 a7  d9 85 d9 87 02 15 00      ...............
ISO639_2_language_code:  ira
event_name_length: 22 (0x16)
event_name: "ÙÛØ§Ù<EM> Ø¨Ø±Ù<EM>Ø§ÙÙ</EM>"  -- Charset: reserved
text_length: 2 (0x02)
text_char: "."  -- Charset: reserved

DVB-DescriptorTag: 84 (0x54)  [= content_descriptor]
descriptor_length: 2 (0x02)
0000:  54 02 00 00                                        T...
Content_nibble_level_1: 0 (0x00)
Content_nibble_level_2: 0 (0x00)
[= reserved]
User_nibble_1: 0 (0x00)
User_nibble_2: 0 (0x00)


DVB-DescriptorTag: 85 (0x55)  [= parental_rating_descriptor]
descriptor_length: 4 (0x04)
0000:  55 04 49 52 4e 00                                  U.IRN.
Country_code:  IRN
Rating:  0 (0x00)  [= undefined]


DVB-DescriptorTag: 78 (0x4e)  [= extended_event_descriptor]
descriptor_length: 59 (0x3b)
0000:  4e 3b 00 69 72 61 00 35  15 d8 aa db 8c d8 b2 d8   N;.ira.5........
0010:  b1 20 d9 87 d8 a7 db 8c  20 d8 b4 d8 a8 da a9 d9   . ...... .......
0020:  87 20 2d 20 d8 a2 da af  d9 87 db 8c 20 d8 a8 d8   . - ........ ...
0030:  a7 d8 b2 d8 b1 da af d8  a7 d9 86 db 8c            .............
descriptor_number: 0 (0x00)
last_descriptor_number: 0 (0x00)
ISO639_2_language_code:  ira
length_of_items: 0 (0x00)

text_length: 53 (0x35)
	text: "ØªÛØ²Ø± Ù</EM>Ø§Û Ø´Ø¨Ú©Ù</EM> - Ø¢Ú¯Ù</EM>Û Ø¨Ø§Ø²Ø±Ú¯Ø§Ù<EM>Û"  -- Charset: reserved

CRC: 2114991661 (0x7e10362d)
	*/
