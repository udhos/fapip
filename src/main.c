/*-GNU-GPL-BEGIN-*
fapip - fast ping probe - measuring packet loss against a host
Copyright (C) 2009  Everton da Silva Marques

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING; if not, write to the
Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
MA 02110-1301 USA
*-GNU-GPL-END-*/

/*
  $Id: main.c,v 1.28 2014/07/30 04:13:17 evertonm Exp $
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/ip_icmp.h>
#include <inttypes.h>
#include <assert.h>

#define FAPIP_IP_UDP_HDR_SIZE (28)
#define FAPIP_ICMP_MIN_SIZE (8) /* ICMP header size */
#define FAPIP_SEQ_TAB_SIZE (0xFFFF + 1)
#define FAPIP_MIN_PKT_SIZE (FAPIP_IP_UDP_HDR_SIZE + FAPIP_ICMP_MIN_SIZE + sizeof(struct timeval))
#define FAPIP_ECHO_DEFAULT_WINDOW (1)

#define FAPIP_UPDATE_MAX(curr,max) \
{                       \
  if ((curr) > (max))   \
    (max) = (curr);     \
}

#define FAPIP_UPDATE_MINMAX(curr,min,max) \
{                            \
  if ((curr) < (min))        \
    (min) = (curr);          \
  FAPIP_UPDATE_MAX(curr,max) \
}

#define PRINTF_U64 "lu"

const char         *fapip_prog_name            = "fapip";
int                 fapip_send_interval_msec   = 100;
int                 fapip_reply_timeout_msec   = 20000;
int                 fapip_report_interval_msec = 2000;
size_t              fapip_packet_length        = FAPIP_MIN_PKT_SIZE;
const char         *fapip_bind_addr            = 0;
struct sockaddr_in  fapip_bind_sockaddr;
const char         *fapip_target_hostname      = 0;
struct sockaddr_in  fapip_target_sockaddr;
uint64_t            fapip_sent                 = 0;
uint64_t            fapip_wait                 = 0;
uint64_t            fapip_recv                 = 0;
uint64_t            fapip_lost_total           = 0;
uint64_t            fapip_lost_min             = 0xFFFFFFFFFFFFFFFFLL;
uint64_t            fapip_lost_max             = 0;
uint64_t            fapip_dup                  = 0;
uint64_t            fapip_late                 = 0;
uint16_t            fapip_id                   = 0;
struct timeval      fapip_seq_tab[FAPIP_SEQ_TAB_SIZE];
uint8_t             fapip_dup_tab[FAPIP_SEQ_TAB_SIZE];
uint64_t            fapip_rtt_min_usec         = 0xFFFFFFFFFFFFFFFFLL;
uint64_t            fapip_rtt_max_usec         = 0;
uint64_t            fapip_rtt_sum_usec         = 0;
uint64_t            fapip_rtt_last_usec        = 0;
uint16_t            fapip_last_seq_recv        = 0;
uint64_t            fapip_jitter_count         = 0;
uint64_t            fapip_jitter_min_usec      = 0xFFFFFFFFFFFFFFFFLL;
uint64_t            fapip_jitter_max_usec      = 0;
uint64_t            fapip_jitter_sum_usec      = 0;
uint64_t            fapip_echo_triggered       = 0; /* window=0 means disabled */
float               fapip_alarm_loss           = .05; /* 5% */
int                 fapip_alarm_silence_msec   = 10000;
uint64_t            fapip_silence_min_usec     = 0xFFFFFFFFFFFFFFFFLL;
uint64_t            fapip_silence_max_usec     = 0;
uint64_t            fapip_silence_sum_usec     = 0;
uint64_t            fapip_silence_recv_count   = 0;
struct timeval      fapip_last_reply;
int                 fapip_alarm_loss_count     = 0;
int                 fapip_alarm_silence_count  = 0;
const char         *fapip_label	               = 0;
int                 fapip_tos                  = -1;

static const char *fapip_version()
{
  return "0.17";
}

static void show_version_brief(FILE *out) 
{
  fprintf(out,
	  "%s: fast ping probe - version %s\n",
	  fapip_prog_name, fapip_version());
}

static void show_version(FILE *out) 
{
  show_version_brief(out);

  fprintf(out,
         "Copyright (C) 2009 Everton da Silva Marques\n"
"\n"
"This program is free software; you can redistribute it and/or\n"
"modify it under the terms of the GNU General Public License\n"
"as published by the Free Software Foundation; either version 2\n"
"of the License, or (at your option) any later version.\n"
"\n"
"This program is distributed in the hope that it will be useful,\n"
"but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
"GNU General Public License for more details.\n"
         );
}

static void usage(FILE *out, const char *prog_name)
{
  fprintf(out,
          "usage: %s [options] host\n"
          "  -h        help\n"
          "  -v        show program version\n"
	  "  -e [win]  enable triggered echo (immediate echo upon reply)\n"
          "            optional window size defaults to %d packet(s)\n"
          "  -b addr   bind to local address\n"
          "  -l bytes  packet length (defaults to %zd)\n"
          "  -r msec   report interval (defaults to %d)\n"
          "  -s msec   send interval (defaults to %d)\n"
          "  -t msec   reply timeout (defaults to %d)\n"
          "  -L %%loss  loss alarm threshold (defaults to %6.3f%%)\n"
          "  -S msec   silence alarm threshold (defaults to %d)\n"
	  "  -T tos    set IP TOS (Type of Service) byte\n"
          "  -d label  yield distinguishing label in report (defaults to undefined)\n",
	  prog_name,
	  FAPIP_ECHO_DEFAULT_WINDOW,
	  fapip_packet_length,
	  fapip_report_interval_msec,
	  fapip_send_interval_msec,
	  fapip_reply_timeout_msec,
	  100 * fapip_alarm_loss,
	  fapip_alarm_silence_msec);
}

static int solve(const char *hostname, struct sockaddr_in *sa)
{
  struct addrinfo hints;
  struct addrinfo *ai_res;
  struct addrinfo *ai;
  int result;

  memset(&hints, 0, sizeof(hints));

  hints.ai_socktype = SOCK_RAW;
  hints.ai_protocol = IPPROTO_ICMP;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_family = PF_INET;
  hints.ai_addrlen = 0;
  hints.ai_addr = 0;
  hints.ai_canonname = 0;

  result = getaddrinfo(hostname, 0, &hints, &ai_res);
  if (result) {
    fprintf(stdout, "%s: %s: getaddrinfo(%s): %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__, hostname,
	    gai_strerror(result));
    return -1;
  }

  for (ai = ai_res; ai; ai = ai->ai_next) {
    if (ai->ai_family == PF_INET) {
      *sa = *(struct sockaddr_in *) ai->ai_addr;
      break;
    }
  }

  freeaddrinfo(ai_res);

  if (!ai) {
    fprintf(stdout, "%s: %s: missing IPv4 address for hostname %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__, hostname);
    return -2;
  }

  return 0;
}

static int nonblock(int fd)
{
  long flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    int e = errno;
    fprintf(stdout, "%s: %s: fcntl(F_GETFL) on fd=%d: errno=%d: %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, e, strerror(e));
    return -1;
  }
  
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
    int e = errno;
    fprintf(stdout, "%s: %s: fcntl(F_SETFL,O_NONBLOCK) on fd=%d: errno=%d: %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, e, strerror(e));
    return -2;
  }

  return 0;
}

static int sock_new()
{
  int sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sock < 0) {
    int e = errno;
    fprintf(stdout, "%s: %s: socket() failure: errno=%d: %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    e, strerror(errno));
    return -1;
  }

  if (fapip_bind_addr) {
    int result = bind(sock, (struct sockaddr *) &fapip_bind_sockaddr,
		      sizeof(fapip_bind_sockaddr));
    if (result) {
      int e = errno;
      fprintf(stdout, "%s: %s: bind(fd=%d,addr=%s) failure: errno=%d: %s\n",
	      fapip_prog_name, __PRETTY_FUNCTION__,
	      sock, inet_ntoa(fapip_bind_sockaddr.sin_addr),
	      e, strerror(errno));
      close(sock);
      return -2;
    }
  }

  if (fapip_tos >= 0) {
    if (setsockopt(sock, SOL_IP, IP_TOS, &fapip_tos, sizeof(fapip_tos))) {
      int e = errno;
      fprintf(stdout, "%s: %s: setsockopt: tos=%d (0x%02x): fd=%d: errno=%d: %s\n",
	      fapip_prog_name, __PRETTY_FUNCTION__,
	      fapip_tos, fapip_tos, sock, e, strerror(e));
      return -3;
    }
  }

  return sock;
}

static void timeval_dump(char *buf, int buf_size,
			 const struct timeval *tv_now)
{
  char tmp[100];
  struct tm tm_now;

  if (localtime_r((time_t*) &tv_now->tv_sec, &tm_now)) {
    strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", &tm_now);
  }
  else {
    snprintf(tmp, sizeof(tmp), "%s", "<timestamp?>");
  }

  snprintf(buf, buf_size, "%s.%03ld", tmp, tv_now->tv_usec / 1000);
}

/*
  RFC 3376: 4.1.2. Checksum

  The Checksum is the 16-bit one's complement of the one's complement
  sum of the whole IGMP message (the entire IP payload).  For
  computing the checksum, the Checksum field is set to zero.  When
  receiving packets, the checksum MUST be verified before processing a
  packet.  [RFC-1071]
*/
static uint16_t in_cksum(const char *buf, int size)
{
  const uint16_t *ptr;
  uint32_t        sum;
  uint16_t        checksum;

  ptr = (const uint16_t *) buf;
  sum = 0;
  while (size > 1) {
    sum += *ptr;
    ++ptr;
    size -= 2;
  }

  /* Add left-over byte, if any */
  if (size > 0)
    sum += (uint16_t) *(const uint8_t *) ptr;

  /* Fold 32-bit sum to 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);

  checksum = ~sum;

  return checksum;
}

static void find_rtt(uint16_t recv_seq,
		     const struct timeval *tv_now,
		     struct in_addr from_addr,
		     const char *icmpdata_buf,
		     size_t icmpdata_len)
{
  struct timeval tv_sent;
  struct timeval tv_rtt;
  uint64_t       rtt_usec;

  if (icmpdata_len < sizeof(struct timeval)) {
    fprintf(stdout, "%s: %s: short ICMP data size=%zd < min=%" PRINTF_U64 " from %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    icmpdata_len, sizeof(struct timeval), inet_ntoa(from_addr));
    return;
  }
  
  memcpy(&tv_sent, icmpdata_buf, sizeof(struct timeval));
  timersub(tv_now, &tv_sent, &tv_rtt); /* tv_rtt = tv_now - tv_sent */

  rtt_usec = tv_rtt.tv_usec + 1000000 * tv_rtt.tv_sec;

  fapip_rtt_sum_usec += rtt_usec;

  FAPIP_UPDATE_MINMAX(rtt_usec, fapip_rtt_min_usec, fapip_rtt_max_usec);

  if (recv_seq == (fapip_last_seq_recv + 1)) {

    ++fapip_jitter_count;

    if (fapip_jitter_count > 1) {
      uint64_t jitter_usec;
      
      jitter_usec = imaxabs(rtt_usec - fapip_rtt_last_usec);
      
      fapip_jitter_sum_usec += jitter_usec;
      
      FAPIP_UPDATE_MINMAX(jitter_usec, fapip_jitter_min_usec, fapip_jitter_max_usec);
    }
  }

  fapip_rtt_last_usec = rtt_usec;
}

static uint64_t check_silence_alarm(const struct timeval *tv_now)
{
  struct timeval tv_silence_elap;
  uint64_t       silence_usec;

  timersub(tv_now, &fapip_last_reply, &tv_silence_elap);
  silence_usec = tv_silence_elap.tv_usec + 1000000 * tv_silence_elap.tv_sec;
  if (silence_usec > (1000 * (uint64_t) fapip_alarm_silence_msec)) {
    char buf_now[100];
    ++fapip_alarm_silence_count;
    timeval_dump(buf_now, sizeof(buf_now), tv_now);
    fprintf(stdout, "%s alarm silence count=%d %" PRINTF_U64 " ms > %d ms\n",
	    buf_now, fapip_alarm_silence_count,
	    silence_usec / 1000, fapip_alarm_silence_msec);
    fflush(stdout);
  }

  fapip_silence_sum_usec += silence_usec;

  FAPIP_UPDATE_MAX(silence_usec, fapip_silence_max_usec);

  return silence_usec;
}

static void icmp_read(int fd, const struct timeval *tv_now,
		      struct timeval *tv_next_send)
{
  struct ip          *ip_hdr;
  size_t              ip_hlen; /* ip header length in bytes */
  struct icmphdr     *icmp_hdr;
  struct sockaddr_in  sockaddr;
  socklen_t           sockaddr_len = sizeof(sockaddr);
  char                buf[1000];
  ssize_t             rd;
  uint16_t            recv_id;
  uint16_t            recv_seq;
  struct timeval      tv_sent;
  int                 icmp_payload_recv;
  char                buf_rtt[20];
  uint64_t            silence_usec;

  rd = recvfrom(fd, buf, sizeof(buf), MSG_DONTWAIT,
		(struct sockaddr *) &sockaddr, &sockaddr_len);
  if (rd < 1) {
    int e = errno;
    fprintf(stdout, "%s: %s: recvfrom(fd=%d): errno=%d: %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, e, strerror(e));
    return;
  }

  ip_hdr = (struct ip *) buf;
  ip_hlen = ip_hdr->ip_hl << 2; /* ip_hl gives length in 4-byte words */

  if (ip_hlen < FAPIP_ICMP_MIN_SIZE) {
    fprintf(stdout, "%s: %s: fd=%d: short ICMP packet size=%zd < min=%d from %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, ip_hlen, FAPIP_ICMP_MIN_SIZE, inet_ntoa(sockaddr.sin_addr));
    return;
  }

  icmp_hdr = (struct icmphdr *) (buf + ip_hlen);

  recv_id = ntohs(icmp_hdr->un.echo.id);
  if (recv_id != fapip_id) {
#if 0
    fprintf(stdout, "%s: %s: fd=%d: recv_id=%u mismatches my_id=%u from %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, recv_id, fapip_id,
	    inet_ntoa(sockaddr.sin_addr));
#endif
    return;
  }

  if (icmp_hdr->type == ICMP_ECHO) {
    /* ignore echo requests */
    return;
  }

  if (icmp_hdr->type != ICMP_ECHOREPLY) {
    fprintf(stdout, "%s: %s: fd=%d: non-echo reply type=%u expected=%u from %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, icmp_hdr->type, ICMP_ECHOREPLY,
	    inet_ntoa(sockaddr.sin_addr));
    return;
  }

  /* update reply silence window */
  silence_usec = check_silence_alarm(tv_now);
  FAPIP_UPDATE_MINMAX(silence_usec, fapip_silence_min_usec, fapip_silence_max_usec);
  ++fapip_silence_recv_count;
  fapip_last_reply = *tv_now;
  
  recv_seq = ntohs(icmp_hdr->un.echo.sequence);

  /* duplicate ? */
  ++fapip_dup_tab[recv_seq];
  if (fapip_dup_tab[recv_seq] > 1) {
    ++fapip_dup;
    fprintf(stdout, "%s: %s: fd=%d: duplicate packet seq=%u from %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, recv_seq, inet_ntoa(sockaddr.sin_addr));
  }

  if (timerisset(&fapip_seq_tab[recv_seq])) {
    char *icmpdata_buf;
    int   icmpdata_len;

    icmpdata_buf = sizeof(struct icmphdr) + (char *) icmp_hdr;
    icmpdata_len = buf + rd - icmpdata_buf;
    find_rtt(recv_seq, tv_now, sockaddr.sin_addr,
	     icmpdata_buf, icmpdata_len);

    timerclear(&fapip_seq_tab[recv_seq]);
    ++fapip_recv;
    --fapip_wait;

    fapip_last_seq_recv = recv_seq;

    if (fapip_echo_triggered) {
      if (fapip_wait < fapip_echo_triggered) {
	/* send next echo ASAP */
	timerclear(tv_next_send);
      }
    }

    return;
  }

  ++fapip_late;

  /* timestamp in reply payload? */
  icmp_payload_recv = rd - (((char *) icmp_hdr + sizeof(*icmp_hdr)) - buf);
  if (icmp_payload_recv < (int) sizeof(tv_sent)) {
    snprintf(buf_rtt, sizeof(buf_rtt), "?");
  }
  else {
    struct timeval tv_elap;
    memcpy(&tv_sent, ((const char *) icmp_hdr) + sizeof(*icmp_hdr), sizeof(tv_sent));
    timersub(tv_now, &tv_sent, &tv_elap); /* tv_elap = tv_now - tv_sent */
    snprintf(buf_rtt, sizeof(buf_rtt), "%" PRINTF_U64 ".%03" PRINTF_U64,
	     tv_elap.tv_sec * 1000,
	     tv_elap.tv_usec / 1000);
  }

  fprintf(stdout, "%s: %s: fd=%d: late packet seq=%u with rtt=%s ms from %s\n",
	  fapip_prog_name, __PRETTY_FUNCTION__,
	  fd, recv_seq, buf_rtt,
	  inet_ntoa(sockaddr.sin_addr));
}

static void icmp_send(int fd, struct timeval *now)
{
  char buf[fapip_packet_length - FAPIP_IP_UDP_HDR_SIZE];
  struct icmphdr *icmp = (struct icmphdr *) buf;
  size_t icmp_len = sizeof(buf);
  ssize_t wr;
  uint16_t seq;

  seq = fapip_sent & 0xFFFF;
  if (!seq) {
    int i;
    /* clear dup table */
    for (i = 0; i < FAPIP_SEQ_TAB_SIZE; ++i) {
      fapip_dup_tab[i] = 0;
    }
  }

  icmp->type             = ICMP_ECHO;
  icmp->code             = 0;
  icmp->checksum         = 0; /* for computing checksum below */
  icmp->un.echo.sequence = htons(seq);
  icmp->un.echo.id       = htons(fapip_id);

  memcpy(buf + sizeof(struct icmphdr), now, sizeof(struct timeval));

  icmp->checksum = in_cksum((const char *) icmp, icmp_len);

  wr = sendto(fd, (const char *) icmp, icmp_len, 0,
	      (const struct sockaddr *) &fapip_target_sockaddr,
	      sizeof(fapip_target_sockaddr));
  if (wr < 1) {
    int e = errno;
    fprintf(stdout, "%s: %s: sendto(fd=%d): sent=%zd/%zd errno=%d: %s\n",
	    fapip_prog_name, __PRETTY_FUNCTION__,
	    fd, wr, icmp_len,
	    e, strerror(e));
    return;
  }

  fapip_seq_tab[seq] = *now;

  ++fapip_sent;
  ++fapip_wait;
}

static void icmp_timeout(const struct timeval *tv_now,
			 const struct timeval *tv_timeout)
{
  uint64_t delta_sent;
  static int prev_sent = 0;
  struct timeval elapsed;
  uint32_t lost = 0;
  int i;

  for (i = 0; i < FAPIP_SEQ_TAB_SIZE; ++i) {
    if (timerisset(&fapip_seq_tab[i])) {
      timersub(tv_now, &fapip_seq_tab[i], &elapsed); /* elapsed = now - timestamp[seq] */
      if (timercmp(&elapsed, tv_timeout, >)) {
	timerclear(&fapip_seq_tab[i]);
	++lost;
      }
    }
  }

  delta_sent = fapip_sent - prev_sent;
  if (delta_sent > 0) {
    float loss;
    loss = (float) lost / delta_sent;
    if (loss > fapip_alarm_loss) {
      char buf_now[100];
      ++fapip_alarm_loss_count;
      timeval_dump(buf_now, sizeof(buf_now), tv_now);
      fprintf(stdout, "%s alarm loss count=%d %6.3f%% > %6.3f%% (lost=%u sent=%" PRINTF_U64 ")\n",
	      buf_now, fapip_alarm_loss_count,
	      100 * loss, 100 * fapip_alarm_loss,
	      lost, delta_sent);
      fflush(stdout);
    }
  }

  fapip_lost_total += lost;
  fapip_wait       -= lost;

  FAPIP_UPDATE_MINMAX(lost, fapip_lost_min, fapip_lost_max);

  prev_sent = fapip_sent;
}

static void icmp_report(const struct timeval *tv_now)
{
  char buf_now[100];
  char buf_rtt_min[23];
  char buf_jitter_min[23];
  char buf_lost_min[23];
  uint64_t rtt_avg = fapip_recv ? fapip_rtt_sum_usec / fapip_recv : 0;
  uint64_t jitter_avg = fapip_jitter_count ? fapip_jitter_sum_usec / fapip_jitter_count : 0;
  uint64_t silence_avg_usec = fapip_silence_recv_count ? fapip_silence_sum_usec / fapip_silence_recv_count : 0;
  static uint32_t report_count = 0;

  if (fapip_lost_min == 0xFFFFFFFFFFFFFFFFLL)
    snprintf(buf_lost_min, sizeof(buf_lost_min), "?");
  else
    snprintf(buf_lost_min, sizeof(buf_lost_min), "%" PRINTF_U64, fapip_lost_min);

  if (fapip_rtt_min_usec == 0xFFFFFFFFFFFFFFFFLL)
    snprintf(buf_rtt_min, sizeof(buf_rtt_min), "?");
  else
    snprintf(buf_rtt_min, sizeof(buf_rtt_min), "%" PRINTF_U64 ".%03" PRINTF_U64,
	     fapip_rtt_min_usec / 1000,
	     fapip_rtt_min_usec % 1000);

  if (fapip_jitter_min_usec == 0xFFFFFFFFFFFFFFFFLL)
    snprintf(buf_jitter_min, sizeof(buf_jitter_min), "?");
  else
    snprintf(buf_jitter_min, sizeof(buf_jitter_min), "%" PRINTF_U64 ".%03" PRINTF_U64,
	     fapip_jitter_min_usec / 1000,
	     fapip_jitter_min_usec % 1000);

  if (!(report_count++ % 10)) {
    fprintf(stdout, "# sn: total sent\n");
    fprintf(stdout, "# rc: total received\n");
    fprintf(stdout, "# wt: total waiting\n");
    fprintf(stdout, "# dp: total duplicate\n");
    fprintf(stdout, "# lt: total late\n");
    fprintf(stdout, "# ls: total lost\n");
    fprintf(stdout, "# ll: minimum lost\n");
    fprintf(stdout, "# lh: maximum lost\n");
    fprintf(stdout, "# rl: minimum RTT (ms)\n");
    fprintf(stdout, "# rv: average RTT (ms)\n");
    fprintf(stdout, "# rh: maximum RTT (ms)\n");
    fprintf(stdout, "# jl: minimum jitter (ms)\n");
    fprintf(stdout, "# jv: average jitter (ms)\n");
    fprintf(stdout, "# jh: maximum jitter (ms)\n");
    fprintf(stdout, "# sl: minimum silence (ms)\n");
    fprintf(stdout, "# sv: average silence (ms)\n");
    fprintf(stdout, "# sh: maximum silence (ms)\n");
    fprintf(stdout, "# al: alarm loss counter\n");
    fprintf(stdout, "# as: alarm silence counter\n");
  }

  timeval_dump(buf_now, sizeof(buf_now), tv_now);

  fprintf(stdout, "%s", buf_now);

  if (fapip_label)
    fprintf(stdout, " %s", fapip_label);

  fprintf(stdout, 
	  " sn %" PRINTF_U64 
	  " rc %" PRINTF_U64
	  " wt %" PRINTF_U64 
	  " dp %" PRINTF_U64
	  " lt %" PRINTF_U64
	  " ls %" PRINTF_U64
	  " ll %s"
	  " lh %" PRINTF_U64,
	  fapip_sent,
	  fapip_recv,
	  fapip_wait,
	  fapip_dup,
	  fapip_late,
	  fapip_lost_total,
	  buf_lost_min,
	  fapip_lost_max);

  if (1) 
    fprintf(stdout,
	    " rl %s"
	    " rv %" PRINTF_U64 ".%03" PRINTF_U64
	    " rh %" PRINTF_U64 ".%03" PRINTF_U64,
	    buf_rtt_min,
	    rtt_avg / 1000,
	    rtt_avg % 1000,
	    fapip_rtt_max_usec / 1000,
	    fapip_rtt_max_usec % 1000);

  if (1) 
    fprintf(stdout, 
	    " jl %s"
	    " jv %" PRINTF_U64 ".%03" PRINTF_U64
	    " jh %" PRINTF_U64 ".%03" PRINTF_U64,
	    buf_jitter_min,
	    jitter_avg / 1000,
	    jitter_avg % 1000,
	    fapip_jitter_max_usec / 1000,
	    fapip_jitter_max_usec % 1000);

  if (1) 
    fprintf(stdout, 
	    " sl %" PRINTF_U64 ".%03" PRINTF_U64
	    " sv %" PRINTF_U64 ".%03" PRINTF_U64
	    " sh %" PRINTF_U64 ".%03" PRINTF_U64,
	    fapip_silence_min_usec / 1000,
	    fapip_silence_min_usec % 1000,
	    silence_avg_usec / 1000,
	    silence_avg_usec % 1000,
	    fapip_silence_max_usec / 1000,
	    fapip_silence_max_usec % 1000);

  fprintf(stdout, " al %d as %d",
	  fapip_alarm_loss_count,
	  fapip_alarm_silence_count);

  fprintf(stdout, "\n");
  fflush(stdout);
}

#ifndef timermin
#define timermin(a, b) (timercmp((a), (b), <) ? (a) : (b))
#endif

#ifndef timerset_msec
#define timerset_msec(tv, msec)               \
  do                                          \
    {                                         \
      (tv)->tv_sec  = (msec) / 1000;          \
      (tv)->tv_usec = ((msec) % 1000) * 1000; \
    }                                         \
  while (0)
#endif

static void do_loop(int fd)
{
  int numfd = fd + 1;
  fd_set fds;
  fd_set fds_tmp;
  struct timeval inc_send;
  struct timeval inc_reply_timeout;
  struct timeval inc_report;
  struct timeval inc_silence_alarm;
  struct timeval next_send;
  struct timeval next_reply_timeout;
  struct timeval next_report;
  struct timeval next_silence_alarm;
  struct timeval timeout;
  struct timeval prev;
  struct timeval now;
  struct timeval elapsed;
  int num = 0;

  timerset_msec(&inc_send, fapip_send_interval_msec);
  timerset_msec(&inc_reply_timeout, fapip_reply_timeout_msec);
  timerset_msec(&inc_report, fapip_report_interval_msec);
  timerset_msec(&inc_silence_alarm, fapip_alarm_silence_msec);

  next_send          = inc_send;
  next_reply_timeout = inc_reply_timeout;
  next_report        = inc_report;
  next_silence_alarm = inc_silence_alarm;

  gettimeofday(&now, 0);
  prev = now;
  fapip_last_reply = now;
  timersub(&prev, &inc_send, &prev); /* prev -= inc_send */

  /* only one fd is monitored */
  FD_ZERO(&fds);
  FD_SET(fd, &fds);

  for (;;) {
    /* how much time has elapsed? */
    timersub(&now, &prev, &elapsed); /* elapsed = now - prev */

    /* act on expired timers */
    if (!timercmp(&elapsed, &next_send, <)) {
      icmp_send(fd, &now);
      timeradd(&inc_send, &next_send, &next_send); /* next_send += inc_send */
    }
    if (!timercmp(&elapsed, &next_reply_timeout, <)) {
      icmp_timeout(&now, &inc_reply_timeout);
      timeradd(&inc_reply_timeout, &next_reply_timeout, &next_reply_timeout); /* next_reply_timeout += inc_reply_timeout */
    }
    if (!timercmp(&elapsed, &next_silence_alarm, <)) {
      check_silence_alarm(&now);
      timeradd(&inc_silence_alarm, &next_silence_alarm, &next_silence_alarm); /* next_silence_alarm += inc_silence_alarm */
    }
    if (!timercmp(&elapsed, &next_report, <)) {
      icmp_report(&now);
      timeradd(&inc_report, &next_report, &next_report); /* next_report += inc_report */
    }

    /* update timers */
    timersub(&next_send, &elapsed, &next_send);                   /* next_send     -= elapsed */
    timersub(&next_reply_timeout, &elapsed, &next_reply_timeout); /* reply_timeout -= elapsed */
    timersub(&next_report, &elapsed, &next_report);               /* report        -= elapsed */
    timersub(&next_silence_alarm, &elapsed, &next_silence_alarm); /* silence_alarm -= elapsed */

    /* find next closest timeout */
    timeout = *timermin(&next_send, &next_reply_timeout);
    timeout = *timermin(&timeout, &next_report);
    timeout = *timermin(&timeout, &next_silence_alarm);

    /* refresh fd set */
    fds_tmp = fds;

    /* wait (data on fd or closest timeout) */
    num = select(numfd, &fds_tmp, 0, 0, &timeout);
    if (num < 0) {
      int e = errno;
      fprintf(stdout, "%s: %s: select(numfd=%d): fd=%d: errno=%d: %s\n",
	      fapip_prog_name, __PRETTY_FUNCTION__,
	      numfd, fd, e, strerror(e));
    }

    /* get current timestamp (ASAP after select) */
    prev = now;
    gettimeofday(&now, 0);

    /* is there data to read from fd ? */ 
    if (num > 0) {
      icmp_read(fd, &now, &next_send);
    }
  }
}

static void do_probe()
{
  int i;

  int sock = sock_new();
  if (sock < 0)
    return;

  if (nonblock(sock)) {
    close(sock);
    return;
  }

  fapip_id = getpid() & 0xFFFF;

  for (i = 0; i < FAPIP_SEQ_TAB_SIZE; ++i) {
    timerclear(&fapip_seq_tab[i]);
    fapip_dup_tab[i] = 0;
  }

  do_loop(sock);
}

int main(int argc, const char *argv[])
{
  int i;

  for (i = 1; i < argc; ++i) {
    const char *arg = argv[i];

    if (!strcmp(arg, "-h")) {
      usage(stdout, fapip_prog_name);
      exit(0);
    }

    if (!strcmp(arg, "-v")) {
      show_version(stdout);
      exit(0);
    }

    if (!strcmp(arg, "-e")) {
      ++i;
      fapip_echo_triggered = FAPIP_ECHO_DEFAULT_WINDOW;
      if (i >= argc) {
	continue;
      }
      if (argv[i][0] == '-') {
	continue;
      }

      const char *w = argv[i];
      int win = atoi(w);
      if (win < 0) {
	fprintf(stdout, "%s: low triggered echo window: %s=%d < 0\n",
		fapip_prog_name, w, win);
	exit(1);
      }

      fapip_echo_triggered = win;

      continue;
    }

    if (!strcmp(arg, "-b")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing bind address\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_bind_addr = argv[i];
      if (solve(fapip_bind_addr, &fapip_bind_sockaddr)) {
	fprintf(stdout, "%s: could not solve bind address: %s\n",
		fapip_prog_name, fapip_bind_addr);
	exit(1);
      }
      continue;
    }

    if (!strcmp(arg, "-l")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing packet size\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_packet_length = atoi(argv[i]);
      if (fapip_packet_length < FAPIP_MIN_PKT_SIZE) {
	fprintf(stdout, "%s: packet size=%zd lower than minimum=%lu\n",
		fapip_prog_name, fapip_packet_length, FAPIP_MIN_PKT_SIZE);
	exit(1);
      }
      continue;
    }

    if (!strcmp(arg, "-L")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing alarm threshold %%loss\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_alarm_loss = atof(argv[i]) / 100;
      continue;
    }

    if (!strcmp(arg, "-s")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing send interval\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_send_interval_msec = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-S")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing alarm silence threshold msec\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_alarm_silence_msec = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-T")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing ToS value\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_tos = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-t")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing reply timeout\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_reply_timeout_msec = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-r")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing report interval\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_report_interval_msec = atoi(argv[i]);
      continue;
    }

    if (!strcmp(arg, "-d")) {
      ++i;
      if (i >= argc) {
        fprintf(stdout, "%s: missing label\n",
		fapip_prog_name);
        exit(1);
      }
      fapip_label = argv[i];
      continue;
    }

    if (arg[0] == '-') {
      fprintf(stdout, "%s: unknown option %d: %s\n",
	      fapip_prog_name, i, arg);
      usage(stdout, fapip_prog_name);
      exit(1);
    }

    if (fapip_target_hostname) {
      fprintf(stdout, "%s: duplicate hostname: %s\n",
	      fapip_prog_name, arg);
      exit(1);
    }

    fapip_target_hostname = arg;
  }

  if (!fapip_target_hostname) {
    fprintf(stdout, "%s: missing hostname\n",
	    fapip_prog_name);
    exit(1);
  }

  show_version_brief(stdout);

  if (solve(fapip_target_hostname, &fapip_target_sockaddr)) {
    fprintf(stdout, "%s: could not solve hostname: %s\n",
	    fapip_prog_name, fapip_target_hostname);
    exit(1);
  }

  fprintf(stdout, "%s: packet_length=%zd send_interval=%d reply_timeout=%d report_interval=%d alarm_loss=%6.3f%% alarm_silence=%d echo_window=%" PRINTF_U64 " tos=%d (0x%02x)\n",
	  fapip_prog_name,
	  fapip_packet_length,
	  fapip_send_interval_msec,
	  fapip_reply_timeout_msec,
	  fapip_report_interval_msec,
	  100 * fapip_alarm_loss,
	  fapip_alarm_silence_msec,
	  fapip_echo_triggered,
	  fapip_tos,
	  fapip_tos);

  if (fapip_bind_addr) {
    char tmp[100];
    strcpy(tmp, inet_ntoa(fapip_bind_sockaddr.sin_addr));
    fprintf(stdout, "%s: probing from %s (%s) to %s (%s)\n",
	    fapip_prog_name,
	    fapip_bind_addr,
	    tmp,
	    fapip_target_hostname,
	    inet_ntoa(fapip_target_sockaddr.sin_addr));
  }
  else {
    fprintf(stdout, "%s: probing %s (%s)\n",
	    fapip_prog_name,
	    fapip_target_hostname,
	    inet_ntoa(fapip_target_sockaddr.sin_addr));
  }

  do_probe();

  fprintf(stdout, "%s: done\n", fapip_prog_name);
  exit(0);
}
