/*
 * block queue tracing application
 *
 * Copyright (C) 2005 Jens Axboe <axboe@suse.de>
 * Copyright (C) 2006 Jens Axboe <axboe@kernel.dk>
 *
 * Rewrite to have a single thread per CPU (managing all devices on that CPU)
 *	Alan D. Brunelle <alan.brunelle@hp.com> - January 2009
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
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <sched.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <locale.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/sendfile.h>

#include "btt/list.h"
#include "blktrace.h"

#ifdef RBLKTRACE
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <rdma/rdma_verbs.h>
#endif

/*
 * You may want to increase this even more, if you are logging at a high
 * rate and see skipped/missed events
 */
#define BUF_SIZE		(512 * 1024)
#define BUF_NR			(4)

#define FILE_VBUF_SIZE		(128 * 1024)

#define DEBUGFS_TYPE		(0x64626720)
#define TRACE_NET_PORT		(8462)

enum {
	Net_none = 0,
	Net_server,
	Net_client,
#ifdef RBLKTRACE
	Net_server_rdma,
	Net_client_rdma,
#endif
};

enum thread_status {
	Th_running,
	Th_leaving,
	Th_error
};

/*
 * Generic stats collected: nevents can be _roughly_ estimated by data_read
 * (discounting pdu...)
 *
 * These fields are updated w/ pdc_dr_update & pdc_nev_update below.
 */
struct pdc_stats {
	unsigned long long data_read;
	unsigned long long nevents;
};

struct devpath {
	struct list_head head;
	char *path;			/* path to device special file */
	char *buts_name;		/* name returned from bt kernel code */
	struct pdc_stats *stats;
	int fd, ncpus;
	unsigned long long drops;

	/*
	 * For piped output only:
	 *
	 * Each tracer will have a tracer_devpath_head that it will add new
	 * data onto. It's list is protected above (tracer_devpath_head.mutex)
	 * and it will signal the processing thread using the dp_cond,
	 * dp_mutex & dp_entries variables above.
	 */
	struct tracer_devpath_head *heads;

	/*
	 * For network server mode only:
	 */
	struct cl_host *ch;
	u32 cl_id;
	time_t cl_connect_time;
	int setup_done;	/* ioctl BLKTRACESETUP done */
	struct io_info *ios;

#ifdef RBLKTRACE
	struct rbt_cli_buf *rdma_bufs;
#endif
};

/*
 * For piped output to stdout we will have each tracer thread (one per dev)
 * tack buffers read from the relay queues on a per-device list.
 *
 * The main thread will then collect trace buffers from each of lists in turn.
 *
 * We will use a mutex to guard each of the trace_buf list. The tracers
 * can then signal the main thread using <dp_cond,dp_mutex> and
 * dp_entries. (When dp_entries is 0, and a tracer adds an entry it will
 * signal. When dp_entries is 0, the main thread will wait for that condition
 * to be signalled.)
 *
 * adb: It may be better just to have a large buffer per tracer per dev,
 * and then use it as a ring-buffer. This would certainly cut down a lot
 * of malloc/free thrashing, at the cost of more memory movements (potentially).
 */
struct trace_buf {
	struct list_head head;
	struct devpath *dpp;
	void *buf;
	int cpu, len;
};

struct tracer_devpath_head {
	pthread_mutex_t mutex;
	struct list_head head;
	struct trace_buf *prev;
};

/*
 * Used to handle the mmap() interfaces for output file (containing traces)
 */
struct mmap_info {
	void *fs_buf;
	unsigned long long fs_size, fs_max_size, fs_off, fs_buf_len;
	unsigned long buf_size, buf_nr;
	int pagesize;
};

/*
 * Each thread doing work on a (client) side of blktrace will have one
 * of these. The ios array contains input/output information, pfds holds
 * poll() data. The volatile's provide flags to/from the main executing
 * thread.
 */
struct tracer {
	struct list_head head;
	struct io_info *ios;
	struct pollfd *pfds;
	pthread_t thread;
	int cpu, nios;
	volatile int status, is_done;
};

/*
 * networking stuff follows. we include a magic number so we know whether
 * to endianness convert or not.
 *
 * The len field is overloaded:
 *	0 - Indicates an "open" - allowing the server to set up for a dev/cpu
 *	1 - Indicates a "close" - Shut down connection orderly
 *
 * The cpu field is overloaded on close: it will contain the number of drops.
 */
struct blktrace_net_hdr {
	u32 magic;		/* same as trace magic */
	char buts_name[32];	/* trace name */
	u32 cpu;		/* for which cpu */
	u32 max_cpus;
	u32 len;		/* length of following trace data */
	u32 cl_id;		/* id for set of client per-cpu connections */
	u32 buf_size;		/* client buf_size for this trace  */
	u32 buf_nr;		/* client buf_nr for this trace  */
	u32 page_size;		/* client page_size for this trace  */
};

/*
 * Each host encountered has one of these. The head is used to link this
 * on to the network server's ch_list. Connections associated with this
 * host are linked on conn_list, and any devices traced on that host
 * are connected on the devpaths list.
 */
struct cl_host {
	struct list_head head;
	struct list_head conn_list;
	struct list_head devpaths;
	struct net_server_s *ns;
	char *hostname;
	struct in_addr cl_in_addr;
	int connects, ndevs, cl_opens;
};

/*
 * Each connection (client to server socket ('fd')) has one of these. A
 * back reference to the host ('ch'), and lists headers (for the host
 * list, and the network server conn_list) are also included.
 */
struct cl_conn {
	struct list_head ch_head, ns_head;
	struct cl_host *ch;
	int fd, ncpus;
	time_t connect_time;
};

/*
 * The network server requires some poll structures to be maintained -
 * one per conection currently on conn_list. The nchs/ch_list values
 * are for each host connected to this server. The addr field is used
 * for scratch as new connections are established.
 */
struct net_server_s {
	struct list_head conn_list;
	struct list_head ch_list;
	struct pollfd *pfds;
	int listen_fd, connects, nchs;
	struct sockaddr_in addr;
};

/*
 * This structure is (generically) used to providide information
 * for a read-to-write set of values.
 *
 * ifn & ifd represent input information
 *
 * ofn, ofd, ofp, obuf & mmap_info are used for output file (optionally).
 */
struct io_info {
	struct devpath *dpp;
	FILE *ofp;
	char *obuf;
	struct cl_conn *nc;	/* Server network connection */

	/*
	 * mmap controlled output files
	 */
	struct mmap_info mmap_info;

	/*
	 * Client network fields
	 */
	unsigned int ready;
	unsigned long long data_queued;

	/*
	 * Input/output file descriptors & names
	 */
	int ifd, ofd;
	char ifn[MAXPATHLEN + 64];
	char ofn[MAXPATHLEN + 64];
};

static char blktrace_version[] = "2.0.0";

/*
 * Linkage to blktrace helper routines (trace conversions)
 */
int data_is_native = -1;

static int ndevs;
static int max_cpus;
static int ncpus;
static cpu_set_t *online_cpus;
static int pagesize;
static int act_mask = ~0U;
static int kill_running_trace;
static int stop_watch;
static int piped_output;

static char *debugfs_path = "/sys/kernel/debug";
static char *output_name;
static char *output_dir;

static unsigned long buf_size = BUF_SIZE;
static unsigned long buf_nr = BUF_NR;

static FILE *pfp;

static LIST_HEAD(devpaths);
static LIST_HEAD(tracers);

static volatile int done;

/*
 * tracer threads add entries, the main thread takes them off and processes
 * them. These protect the dp_entries variable.
 */
static pthread_cond_t dp_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t dp_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int dp_entries;

/*
 * These synchronize master / thread interactions.
 */
static pthread_cond_t mt_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t mt_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int nthreads_running;
static volatile int nthreads_leaving;
static volatile int nthreads_error;
static volatile int tracers_run;

/*
 * network cmd line params
 */
static struct sockaddr_in hostname_addr;
static char hostname[MAXHOSTNAMELEN];
static int net_port = TRACE_NET_PORT;
static int net_use_sendfile = 1;
static int net_mode;
static int *cl_fds;

static int (*handle_pfds)(struct tracer *, int, int);
static int (*handle_list)(struct tracer_devpath_head *, struct list_head *);

#ifdef RBLKTRACE

static bool use_rdma = false;
static char rdma_port[sizeof("65535")];
static int max_ncpus = 32;
static int max_ndevs = 4;
static int rdma_interval = 100;// msec

#endif

#ifdef RBLKTRACE
#define S_OPTS	"d:a:A:r:o:kw:vVb:n:D:lh:p:sI:R::m:M:i:"
#else
#define S_OPTS	"d:a:A:r:o:kw:vVb:n:D:lh:p:sI:"
#endif

static struct option l_opts[] = {
	{
		.name = "dev",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'd'
	},
	{
		.name = "input-devs",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'I'
	},
	{
		.name = "act-mask",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'a'
	},
	{
		.name = "set-mask",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'A'
	},
	{
		.name = "relay",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'r'
	},
	{
		.name = "output",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'o'
	},
	{
		.name = "kill",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'k'
	},
	{
		.name = "stopwatch",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'w'
	},
	{
		.name = "version",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'v'
	},
	{
		.name = "version",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'V'
	},
	{
		.name = "buffer-size",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'b'
	},
	{
		.name = "num-sub-buffers",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'n'
	},
	{
		.name = "output-dir",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'D'
	},
	{
		.name = "listen",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 'l'
	},
	{
		.name = "host",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'h'
	},
	{
		.name = "port",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'p'
	},
	{
		.name = "no-sendfile",
		.has_arg = no_argument,
		.flag = NULL,
		.val = 's'
	},
#ifdef RBLKTRACE
	// RDMA network mode arguments
	{
		.name = "rdma",
		.has_arg = optional_argument,
		.flag = NULL,
		.val = 'R'
	},
	{
		.name = "max-ncpus",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'm'
	},
	{
		.name = "max-ndevs",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'M'
	},
	{
		.name = "rdma-interval",
		.has_arg = required_argument,
		.flag = NULL,
		.val = 'P'
	},
#endif// RBLKTRACE
	{
		.name = NULL,
	}
};

static char usage_str[] = "\n\n"
	"-d <dev>             | --dev=<dev>\n"
	"[ -r <debugfs path>  | --relay=<debugfs path> ]\n"
	"[ -o <file>          | --output=<file>]\n"
	"[ -D <dir>           | --output-dir=<dir>\n"
	"[ -w <time>          | --stopwatch=<time>]\n"
	"[ -a <action field>  | --act-mask=<action field>]\n"
	"[ -A <action mask>   | --set-mask=<action mask>]\n"
	"[ -b <size>          | --buffer-size]\n"
	"[ -n <number>        | --num-sub-buffers=<number>]\n"
	"[ -l                 | --listen]\n"
	"[ -h <hostname>      | --host=<hostname>]\n"
	"[ -p <port number>   | --port=<port number>]\n"
	"[ -s                 | --no-sendfile]\n"
	"[ -I <devs file>     | --input-devs=<devs file>]\n"
	"[ -v <version>       | --version]\n"
	"[ -V <version>       | --version]\n"
#ifdef RBLKTRACE
	"[ -R[<port number>]  | --rdma[=<port number>]]\n"
	"[ -m <number>        | --max-ncpus=<number>]\n"
	"[ -M <number>        | --max-ndevs=<number>]\n"
	"[ -i <msec>          | --rdma-interval=<msec>]\n"
#endif

	"\t-d Use specified device. May also be given last after options\n"
	"\t-r Path to mounted debugfs, defaults to /sys/kernel/debug\n"
	"\t-o File(s) to send output to\n"
	"\t-D Directory to prepend to output file names\n"
	"\t-w Stop after defined time, in seconds\n"
	"\t-a Only trace specified actions. See documentation\n"
	"\t-A Give trace mask as a single value. See documentation\n"
	"\t-b Sub buffer size in KiB (default 512)\n"
#ifdef RBLKTRACE
	"\t-n Number of sub buffers (default 16 in RDMA mode, 4 otherwise)\n"
#else
	"\t-n Number of sub buffers (default 4)\n"
#endif
	"\t-l Run in network listen mode (blktrace server)\n"
	"\t-h Run in network client mode, connecting to the given host\n"
	"\t-p Network port to use (default 8462)\n"
	"\t-s Make the network client NOT use sendfile() to transfer data\n"
	"\t-I Add devices found in <devs file>\n"
	"\t-v Print program version info\n"
	"\t-V Print program version info\n"
#ifdef RBLKTRACE
	"\t-R Use RDMA network mode; default port 8463\n"
	"\t-m Maximum number of client CPUs (default 32)\n"
	"\t-M Maximum number of client devices (default 4)\n"
	"\t-i RDMA server read interval in milliseconds (default 100)\n"
#endif
	"\n";

static void clear_events(struct pollfd *pfd)
{
	pfd->events = 0;
	pfd->revents = 0;
}

static inline int net_client_use_sendfile(void)
{
	return net_mode == Net_client && net_use_sendfile;
}

static inline int net_client_use_send(void)
{
	return net_mode == Net_client && !net_use_sendfile;
}

static inline int use_tracer_devpaths(void)
{
	return piped_output || net_client_use_send();
}

static inline int in_addr_eq(struct in_addr a, struct in_addr b)
{
	return a.s_addr == b.s_addr;
}

static inline void pdc_dr_update(struct devpath *dpp, int cpu, int data_read)
{
	dpp->stats[cpu].data_read += data_read;
}

static inline void pdc_nev_update(struct devpath *dpp, int cpu, int nevents)
{
	dpp->stats[cpu].nevents += nevents;
}

static void show_usage(char *prog)
{
	fprintf(stderr, "Usage: %s %s", prog, usage_str);
}

/*
 * Create a timespec 'msec' milliseconds into the future
 */
static inline void make_timespec(struct timespec *tsp, long delta_msec)
{
	struct timeval now;

	gettimeofday(&now, NULL);
	tsp->tv_sec = now.tv_sec;
	tsp->tv_nsec = 1000L * now.tv_usec;

	tsp->tv_nsec += (delta_msec * 1000000L);
	if (tsp->tv_nsec > 1000000000L) {
		long secs = tsp->tv_nsec / 1000000000L;

		tsp->tv_sec += secs;
		tsp->tv_nsec -= (secs * 1000000000L);
	}
}

/*
 * Add a timer to ensure wait ends
 */
static void t_pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
	struct timespec ts;

	make_timespec(&ts, 50);
	pthread_cond_timedwait(cond, mutex, &ts);
}

static void unblock_tracers(void)
{
	pthread_mutex_lock(&mt_mutex);
	tracers_run = 1;
	pthread_cond_broadcast(&mt_cond);
	pthread_mutex_unlock(&mt_mutex);
}

static void tracer_wait_unblock(struct tracer *tp)
{
	pthread_mutex_lock(&mt_mutex);
	while (!tp->is_done && !tracers_run)
		pthread_cond_wait(&mt_cond, &mt_mutex);
	pthread_mutex_unlock(&mt_mutex);
}

static void tracer_signal_ready(struct tracer *tp,
				enum thread_status th_status,
				int status)
{
	pthread_mutex_lock(&mt_mutex);
	tp->status = status;

	if (th_status == Th_running)
		nthreads_running++;
	else if (th_status == Th_error)
		nthreads_error++;
	else
		nthreads_leaving++;

	pthread_cond_signal(&mt_cond);
	pthread_mutex_unlock(&mt_mutex);
}

static void wait_tracers_ready(int ncpus_started)
{
	pthread_mutex_lock(&mt_mutex);
	while ((nthreads_running + nthreads_error) < ncpus_started)
		t_pthread_cond_wait(&mt_cond, &mt_mutex);
	pthread_mutex_unlock(&mt_mutex);
}

static void wait_tracers_leaving(void)
{
	pthread_mutex_lock(&mt_mutex);
	while (nthreads_leaving < nthreads_running)
		t_pthread_cond_wait(&mt_cond, &mt_mutex);
	pthread_mutex_unlock(&mt_mutex);
}

static void init_mmap_info(struct mmap_info *mip)
{
	mip->buf_size = buf_size;
	mip->buf_nr = buf_nr;
	mip->pagesize = pagesize;
}

static void net_close_connection(int *fd)
{
	shutdown(*fd, SHUT_RDWR);
	close(*fd);
	*fd = -1;
}

static void dpp_free(struct devpath *dpp)
{
	if (dpp->stats)
		free(dpp->stats);
	if (dpp->ios)
		free(dpp->ios);
	if (dpp->path)
		free(dpp->path);
	if (dpp->buts_name)
		free(dpp->buts_name);
	free(dpp);
}

static int lock_on_cpu(int cpu)
{
	cpu_set_t * cpu_mask;
	size_t size;

	cpu_mask = CPU_ALLOC(max_cpus);
	size = CPU_ALLOC_SIZE(max_cpus);

	CPU_ZERO_S(size, cpu_mask);
	CPU_SET_S(cpu, size, cpu_mask);
	if (sched_setaffinity(0, size, cpu_mask) < 0) {
		CPU_FREE(cpu_mask);		
		return errno;
	}

	CPU_FREE(cpu_mask);		
	return 0;
}

static int increase_limit(int resource, rlim_t increase)
{
	struct rlimit rlim;
	int save_errno = errno;

	if (!getrlimit(resource, &rlim)) {
		rlim.rlim_cur += increase;
		if (rlim.rlim_cur >= rlim.rlim_max)
			rlim.rlim_max = rlim.rlim_cur + increase;

		if (!setrlimit(resource, &rlim))
			return 1;
	}

	errno = save_errno;
	return 0;
}

static int handle_open_failure(void)
{
	if (errno == ENFILE || errno == EMFILE)
		return increase_limit(RLIMIT_NOFILE, 16);
	return 0;
}

static int handle_mem_failure(size_t length)
{
	if (errno == ENFILE)
		return handle_open_failure();
	else if (errno == ENOMEM)
		return increase_limit(RLIMIT_MEMLOCK, 2 * length);
	return 0;
}

static FILE *my_fopen(const char *path, const char *mode)
{
	FILE *fp;

	do {
		fp = fopen(path, mode);
	} while (fp == NULL && handle_open_failure());

	return fp;
}

static int my_open(const char *path, int flags)
{
	int fd;

	do {
		fd = open(path, flags);
	} while (fd < 0 && handle_open_failure());

	return fd;
}

#ifdef RBLKTRACE

static int my_open3(const char *path, int flags, mode_t mode)
{
	int fd;

	do {
		fd = open(path, flags, mode);
	} while (fd < 0 && handle_open_failure());

	return fd;
}

#endif// RBLKTRACE

static int my_socket(int domain, int type, int protocol)
{
	int fd;

	do {
		fd = socket(domain, type, protocol);
	} while (fd < 0 && handle_open_failure());

	return fd;
}

static int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int fd;

	do {
		fd = accept(sockfd, addr, addrlen);
	} while (fd < 0 && handle_open_failure());

	return fd;
}

static void *my_mmap(void *addr, size_t length, int prot, int flags, int fd,
		     off_t offset)
{
	void *new;

	do {
		new = mmap(addr, length, prot, flags, fd, offset);
	} while (new == MAP_FAILED && handle_mem_failure(length));

	return new;
}

static int my_mlock(struct tracer *tp,
		    const void *addr, size_t len)
{
	int ret, retry = 0;

	do {
		ret = mlock(addr, len);
		if ((retry >= 10) && tp && tp->is_done)
			break;
		retry++;
	} while (ret < 0 && handle_mem_failure(len));

	return ret;
}

static int setup_mmap(int fd, unsigned int maxlen,
		      struct mmap_info *mip,
		      struct tracer *tp)
{
	if (mip->fs_off + maxlen > mip->fs_buf_len) {
		unsigned long nr = max(16, mip->buf_nr);

		if (mip->fs_buf) {
			munlock(mip->fs_buf, mip->fs_buf_len);
			munmap(mip->fs_buf, mip->fs_buf_len);
			mip->fs_buf = NULL;
		}

		mip->fs_off = mip->fs_size & (mip->pagesize - 1);
		mip->fs_buf_len = (nr * mip->buf_size) - mip->fs_off;
		mip->fs_max_size += mip->fs_buf_len;

		if (ftruncate(fd, mip->fs_max_size) < 0) {
			perror("setup_mmap: ftruncate");
			return 1;
		}

		mip->fs_buf = my_mmap(NULL, mip->fs_buf_len, PROT_WRITE,
				      MAP_SHARED, fd,
				      mip->fs_size - mip->fs_off);
		if (mip->fs_buf == MAP_FAILED) {
			perror("setup_mmap: mmap");
			return 1;
		}
		if (my_mlock(tp, mip->fs_buf, mip->fs_buf_len) < 0) {
			perror("setup_mlock: mlock");
			return 1;
		}
	}

	return 0;
}

static int __stop_trace(int fd)
{
	/*
	 * Should be stopped, don't complain if it isn't
	 */
	ioctl(fd, BLKTRACESTOP);
	return ioctl(fd, BLKTRACETEARDOWN);
}

static int write_data(char *buf, int len)
{
	int ret;

rewrite:
	ret = fwrite(buf, len, 1, pfp);
	if (ferror(pfp) || ret != 1) {
		if (errno == EINTR) {
			clearerr(pfp);
			goto rewrite;
		}

		if (!piped_output || (errno != EPIPE && errno != EBADF)) {
			fprintf(stderr, "write(%d) failed: %d/%s\n",
				len, errno, strerror(errno));
		}
		goto err;
	}

	fflush(pfp);
	return 0;

err:
	clearerr(pfp);
	return 1;
}

/*
 * Returns the number of bytes read (successfully)
 */
static int __net_recv_data(int fd, void *buf, unsigned int len)
{
	unsigned int bytes_left = len;

	while (bytes_left && !done) {
		int ret = recv(fd, buf, bytes_left, MSG_WAITALL);

		if (ret == 0)
			break;
		else if (ret < 0) {
			if (errno == EAGAIN) {
				usleep(50);
				continue;
			}
			perror("server: net_recv_data: recv failed");
			break;
		} else {
			buf += ret;
			bytes_left -= ret;
		}
	}

	return len - bytes_left;
}

static int net_recv_data(int fd, void *buf, unsigned int len)
{
	return __net_recv_data(fd, buf, len);
}

/*
 * Returns number of bytes written
 */
static int net_send_data(int fd, void *buf, unsigned int buf_len)
{
	int ret;
	unsigned int bytes_left = buf_len;

	while (bytes_left) {
		ret = send(fd, buf, bytes_left, 0);
		if (ret < 0) {
			perror("send");
			break;
		}

		buf += ret;
		bytes_left -= ret;
	}

	return buf_len - bytes_left;
}

static int net_send_header(int fd, int cpu, char *buts_name, int len)
{
	struct blktrace_net_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));

	hdr.magic = BLK_IO_TRACE_MAGIC;
	memset(hdr.buts_name, 0, sizeof(hdr.buts_name));
	strncpy(hdr.buts_name, buts_name, sizeof(hdr.buts_name));
	hdr.buts_name[sizeof(hdr.buts_name) - 1] = '\0';
	hdr.cpu = cpu;
	hdr.max_cpus = max_cpus;
	hdr.len = len;
	hdr.cl_id = getpid();
	hdr.buf_size = buf_size;
	hdr.buf_nr = buf_nr;
	hdr.page_size = pagesize;

	return net_send_data(fd, &hdr, sizeof(hdr)) != sizeof(hdr);
}

static void net_send_open_close(int fd, int cpu, char *buts_name, int len)
{
	struct blktrace_net_hdr ret_hdr;

	net_send_header(fd, cpu, buts_name, len);
	net_recv_data(fd, &ret_hdr, sizeof(ret_hdr));
}

static void net_send_open(int fd, int cpu, char *buts_name)
{
	net_send_open_close(fd, cpu, buts_name, 0);
}

static void net_send_close(int fd, char *buts_name, int drops)
{
	/*
	 * Overload CPU w/ number of drops
	 *
	 * XXX: Need to clear/set done around call - done=1 (which
	 * is true here) stops reads from happening... :-(
	 */
	done = 0;
	net_send_open_close(fd, drops, buts_name, 1);
	done = 1;
}

static void ack_open_close(int fd, char *buts_name)
{
	net_send_header(fd, 0, buts_name, 2);
}

static void net_send_drops(int fd)
{
	struct list_head *p;

	__list_for_each(p, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);

		net_send_close(fd, dpp->buts_name, dpp->drops);
	}
}

/*
 * Returns:
 *	 0: "EOF"
 *	 1: OK
 *	-1: Error
 */
static int net_get_header(struct cl_conn *nc, struct blktrace_net_hdr *bnh)
{
	int bytes_read;
	int fl = fcntl(nc->fd, F_GETFL);

	fcntl(nc->fd, F_SETFL, fl | O_NONBLOCK);
	bytes_read = __net_recv_data(nc->fd, bnh, sizeof(*bnh));
	fcntl(nc->fd, F_SETFL, fl & ~O_NONBLOCK);

	if (bytes_read == sizeof(*bnh))
		return 1;
	else if (bytes_read == 0)
		return 0;
	else
		return -1;
}

static int net_setup_addr(void)
{
	struct sockaddr_in *addr = &hostname_addr;

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(net_port);

	if (inet_aton(hostname, &addr->sin_addr) != 1) {
		struct hostent *hent;
retry:
		hent = gethostbyname(hostname);
		if (!hent) {
			if (h_errno == TRY_AGAIN) {
				usleep(100);
				goto retry;
			} else if (h_errno == NO_RECOVERY) {
				fprintf(stderr, "gethostbyname(%s)"
					"non-recoverable error encountered\n",
					hostname);
			} else {
				/*
				 * HOST_NOT_FOUND, NO_ADDRESS or NO_DATA
				 */
				fprintf(stderr, "Host %s not found\n",
					hostname);
			}
			return 1;
		}

		memcpy(&addr->sin_addr, hent->h_addr, 4);
		memset(hostname, 0, sizeof(hostname));
		strncpy(hostname, hent->h_name, sizeof(hostname));
		hostname[sizeof(hostname) - 1] = '\0';
	}

	return 0;
}

static int net_setup_client(void)
{
	int fd;
	struct sockaddr_in *addr = &hostname_addr;

	fd = my_socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("client: socket");
		return -1;
	}

	if (connect(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) {
		if (errno == ECONNREFUSED)
			fprintf(stderr,
				"\nclient: Connection to %s refused, "
				"perhaps the server is not started?\n\n",
				hostname);
		else
			perror("client: connect");

		close(fd);
		return -1;
	}

	return fd;
}

static int open_client_connections(void)
{
	int cpu;
	size_t alloc_size = CPU_ALLOC_SIZE(max_cpus);

	cl_fds = calloc(ncpus, sizeof(*cl_fds));
	for (cpu = 0; cpu < max_cpus; cpu++) {
		if (!CPU_ISSET_S(cpu, alloc_size, online_cpus))
			continue;
		cl_fds[cpu] = net_setup_client();
		if (cl_fds[cpu] < 0)
			goto err;
	}
	return 0;

err:
	while (cpu > 0)
		close(cl_fds[cpu--]);
	free(cl_fds);
	return 1;
}

static void close_client_connections(void)
{
	if (cl_fds) {
		int cpu, *fdp;
		size_t alloc_size = CPU_ALLOC_SIZE(max_cpus);

		for (cpu = 0, fdp = cl_fds; cpu < max_cpus; cpu++, fdp++) {
			if (!CPU_ISSET_S(cpu, alloc_size, online_cpus))
				continue;
			if (*fdp >= 0) {
				net_send_drops(*fdp);
				net_close_connection(fdp);
			}
		}
		free(cl_fds);
	}
}

static int setup_buts(void)
{
	struct list_head *p;
	int ret = 0;

	__list_for_each(p, &devpaths) {
		struct blk_user_trace_setup buts;
		struct devpath *dpp = list_entry(p, struct devpath, head);

		memset(&buts, 0, sizeof(buts));
		buts.buf_size = buf_size;
		buts.buf_nr = buf_nr;
		buts.act_mask = act_mask;
#ifdef RBLKTRACE
		buts.use_rdma = (net_mode == Net_client_rdma);
#endif

		if (ioctl(dpp->fd, BLKTRACESETUP, &buts) >= 0) {
			dpp->ncpus = max_cpus;
			dpp->buts_name = strdup(buts.name);
			dpp->setup_done = 1;
			if (dpp->stats)
				free(dpp->stats);
			dpp->stats = calloc(dpp->ncpus, sizeof(*dpp->stats));
			memset(dpp->stats, 0, dpp->ncpus * sizeof(*dpp->stats));
		} else {
			fprintf(stderr, "BLKTRACESETUP(2) %s failed: %d/%s\n",
				dpp->path, errno, strerror(errno));
			ret++;
		}
	}

	return ret;
}

static void start_buts(void)
{
	struct list_head *p;

	__list_for_each(p, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);

		if (ioctl(dpp->fd, BLKTRACESTART) < 0) {
			fprintf(stderr, "BLKTRACESTART %s failed: %d/%s\n",
				dpp->path, errno, strerror(errno));
		}
	}
}

static int get_drops(struct devpath *dpp)
{
	int fd, drops = 0;
	char fn[MAXPATHLEN + 64], tmp[256];

	snprintf(fn, sizeof(fn), "%s/block/%s/dropped", debugfs_path,
		 dpp->buts_name);

	fd = my_open(fn, O_RDONLY);
	if (fd < 0) {
		/*
		 * This may be ok: the kernel may not support
		 * dropped counts.
		 */
		if (errno != ENOENT)
			fprintf(stderr, "Could not open %s: %d/%s\n",
				fn, errno, strerror(errno));
		return 0;
	} else if (read(fd, tmp, sizeof(tmp)) < 0) {
		fprintf(stderr, "Could not read %s: %d/%s\n",
			fn, errno, strerror(errno));
	} else
		drops = atoi(tmp);
	close(fd);

	return drops;
}

static void get_all_drops(void)
{
	struct list_head *p;

	__list_for_each(p, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);

		dpp->drops = get_drops(dpp);
	}
}

static inline struct trace_buf *alloc_trace_buf(int cpu, int bufsize)
{
	struct trace_buf *tbp;

	tbp = malloc(sizeof(*tbp) + bufsize);
	INIT_LIST_HEAD(&tbp->head);
	tbp->len = 0;
	tbp->buf = (void *)(tbp + 1);
	tbp->cpu = cpu;
	tbp->dpp = NULL;	/* Will be set when tbp is added */

	return tbp;
}

static void free_tracer_heads(struct devpath *dpp)
{
	int cpu;
	struct tracer_devpath_head *hd;

	for (cpu = 0, hd = dpp->heads; cpu < max_cpus; cpu++, hd++) {
		if (hd->prev)
			free(hd->prev);

		pthread_mutex_destroy(&hd->mutex);
	}
	free(dpp->heads);
}

static int setup_tracer_devpaths(void)
{
	struct list_head *p;

	if (net_client_use_send())
		if (open_client_connections())
			return 1;

	__list_for_each(p, &devpaths) {
		int cpu;
		struct tracer_devpath_head *hd;
		struct devpath *dpp = list_entry(p, struct devpath, head);

		dpp->heads = calloc(max_cpus, sizeof(struct tracer_devpath_head));
		for (cpu = 0, hd = dpp->heads; cpu < max_cpus; cpu++, hd++) {
			INIT_LIST_HEAD(&hd->head);
			pthread_mutex_init(&hd->mutex, NULL);
			hd->prev = NULL;
		}
	}

	return 0;
}

static inline void add_trace_buf(struct devpath *dpp, int cpu,
						struct trace_buf **tbpp)
{
	struct trace_buf *tbp = *tbpp;
	struct tracer_devpath_head *hd = &dpp->heads[cpu];

	tbp->dpp = dpp;

	pthread_mutex_lock(&hd->mutex);
	list_add_tail(&tbp->head, &hd->head);
	pthread_mutex_unlock(&hd->mutex);

	*tbpp = alloc_trace_buf(cpu, buf_size);
}

static inline void incr_entries(int entries_handled)
{
	pthread_mutex_lock(&dp_mutex);
	if (dp_entries == 0)
		pthread_cond_signal(&dp_cond);
	dp_entries += entries_handled;
	pthread_mutex_unlock(&dp_mutex);
}

static void decr_entries(int handled)
{
	pthread_mutex_lock(&dp_mutex);
	dp_entries -= handled;
	pthread_mutex_unlock(&dp_mutex);
}

static int wait_empty_entries(void)
{
	pthread_mutex_lock(&dp_mutex);
	while (!done && dp_entries == 0)
		t_pthread_cond_wait(&dp_cond, &dp_mutex);
	pthread_mutex_unlock(&dp_mutex);

	return !done;
}

static int add_devpath(char *path)
{
	int fd;
	struct devpath *dpp;
	struct list_head *p;

	/*
	 * Verify device is not duplicated
	 */
	__list_for_each(p, &devpaths) {
	       struct devpath *tmp = list_entry(p, struct devpath, head);
	       if (!strcmp(tmp->path, path))
		        return 0;
	}
	/*
	 * Verify device is valid before going too far
	 */
	fd = my_open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "Invalid path %s specified: %d/%s\n",
			path, errno, strerror(errno));
		return 1;
	}

	dpp = malloc(sizeof(*dpp));
	memset(dpp, 0, sizeof(*dpp));
	dpp->path = strdup(path);
	dpp->fd = fd;
	ndevs++;
	list_add_tail(&dpp->head, &devpaths);

	return 0;
}

static void rel_devpaths(void)
{
	struct list_head *p, *q;

	list_for_each_safe(p, q, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);

		list_del(&dpp->head);
		if (dpp->setup_done)
			__stop_trace(dpp->fd);
		close(dpp->fd);

		if (dpp->heads)
			free_tracer_heads(dpp);

		dpp_free(dpp);
		ndevs--;
	}
}

static int flush_subbuf_net(struct trace_buf *tbp)
{
	int fd = cl_fds[tbp->cpu];
	struct devpath *dpp = tbp->dpp;

	if (net_send_header(fd, tbp->cpu, dpp->buts_name, tbp->len))
		return 1;
	else if (net_send_data(fd, tbp->buf, tbp->len) != tbp->len)
		return 1;

	return 0;
}

static int
handle_list_net(__attribute__((__unused__))struct tracer_devpath_head *hd,
		struct list_head *list)
{
	struct trace_buf *tbp;
	struct list_head *p, *q;
	int entries_handled = 0;

	list_for_each_safe(p, q, list) {
		tbp = list_entry(p, struct trace_buf, head);

		list_del(&tbp->head);
		entries_handled++;

		if (cl_fds[tbp->cpu] >= 0) {
			if (flush_subbuf_net(tbp)) {
				close(cl_fds[tbp->cpu]);
				cl_fds[tbp->cpu] = -1;
			}
		}

		free(tbp);
	}

	return entries_handled;
}

/*
 * Tack 'tbp's buf onto the tail of 'prev's buf
 */
static struct trace_buf *tb_combine(struct trace_buf *prev,
				    struct trace_buf *tbp)
{
	unsigned long tot_len;

	tot_len = prev->len + tbp->len;
	if (tot_len > buf_size) {
		/*
		 * tbp->head isn't connected (it was 'prev'
		 * so it had been taken off of the list
		 * before). Therefore, we can realloc
		 * the whole structures, as the other fields
		 * are "static".
		 */
		prev = realloc(prev, sizeof(*prev) + tot_len);
		prev->buf = (void *)(prev + 1);
	}

	memcpy(prev->buf + prev->len, tbp->buf, tbp->len);
	prev->len = tot_len;

	free(tbp);
	return prev;
}

static int handle_list_file(struct tracer_devpath_head *hd,
			    struct list_head *list)
{
	int off, t_len, nevents;
	struct blk_io_trace *t;
	struct list_head *p, *q;
	int entries_handled = 0;
	struct trace_buf *tbp, *prev;

	prev = hd->prev;
	list_for_each_safe(p, q, list) {
		tbp = list_entry(p, struct trace_buf, head);
		list_del(&tbp->head);
		entries_handled++;

		/*
		 * If there was some leftover before, tack this new
		 * entry onto the tail of the previous one.
		 */
		if (prev)
			tbp = tb_combine(prev, tbp);

		/*
		 * See how many whole traces there are - send them
		 * all out in one go.
		 */
		off = 0;
		nevents = 0;
		while (off + (int)sizeof(*t) <= tbp->len) {
			t = (struct blk_io_trace *)(tbp->buf + off);
			t_len = sizeof(*t) + t->pdu_len;
			if (off + t_len > tbp->len)
				break;

			off += t_len;
			nevents++;
		}
		if (nevents)
			pdc_nev_update(tbp->dpp, tbp->cpu, nevents);

		/*
		 * Write any full set of traces, any remaining data is kept
		 * for the next pass.
		 */
		if (off) {
			if (write_data(tbp->buf, off) || off == tbp->len) {
				free(tbp);
				prev = NULL;
			}
			else {
				/*
				 * Move valid data to beginning of buffer
				 */
				tbp->len -= off;
				memmove(tbp->buf, tbp->buf + off, tbp->len);
				prev = tbp;
			}
		} else
			prev = tbp;
	}
	hd->prev = prev;

	return entries_handled;
}

static void __process_trace_bufs(void)
{
	int cpu;
	struct list_head *p;
	struct list_head list;
	int handled = 0;

	__list_for_each(p, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);
		struct tracer_devpath_head *hd = dpp->heads;

		for (cpu = 0; cpu < max_cpus; cpu++, hd++) {
			pthread_mutex_lock(&hd->mutex);
			if (list_empty(&hd->head)) {
				pthread_mutex_unlock(&hd->mutex);
				continue;
			}

			list_replace_init(&hd->head, &list);
			pthread_mutex_unlock(&hd->mutex);

			handled += handle_list(hd, &list);
		}
	}

	if (handled)
		decr_entries(handled);
}

static void process_trace_bufs(void)
{
	while (wait_empty_entries())
		__process_trace_bufs();
}

static void clean_trace_bufs(void)
{
	/*
	 * No mutex needed here: we're only reading from the lists,
	 * tracers are done
	 */
	while (dp_entries)
		__process_trace_bufs();
}

static inline void read_err(int cpu, char *ifn)
{
	if (errno != EAGAIN)
		fprintf(stderr, "Thread %d failed read of %s: %d/%s\n",
			cpu, ifn, errno, strerror(errno));
}

static int net_sendfile(struct io_info *iop)
{
	int ret;

	ret = sendfile(iop->ofd, iop->ifd, NULL, iop->ready);
	if (ret < 0) {
		perror("sendfile");
		return 1;
	} else if (ret < (int)iop->ready) {
		fprintf(stderr, "short sendfile send (%d of %d)\n",
			ret, iop->ready);
		return 1;
	}

	return 0;
}

static inline int net_sendfile_data(struct tracer *tp, struct io_info *iop)
{
	struct devpath *dpp = iop->dpp;

	if (net_send_header(iop->ofd, tp->cpu, dpp->buts_name, iop->ready))
		return 1;
	return net_sendfile(iop);
}

static int fill_ofname(char *dst, int dstlen, const char *subdir, const char *buts_name, int cpu)
{
	int len;
	struct stat sb;

	if (output_dir)
		len = snprintf(dst, dstlen, "%s/", output_dir);
	else
		len = snprintf(dst, dstlen, "./");

	if (subdir)
		len += snprintf(dst + len, dstlen - len, "%s", subdir);

	if (stat(dst, &sb) < 0) {
		if (errno != ENOENT) {
			fprintf(stderr,
				"Destination dir %s stat failed: %d/%s\n",
				dst, errno, strerror(errno));
			return 1;
		}
		/*
		 * There is no synchronization between multiple threads
		 * trying to create the directory at once.  It's harmless
		 * to let them try, so just detect the problem and move on.
		 */
		if (mkdir(dst, 0755) < 0 && errno != EEXIST) {
			fprintf(stderr,
				"Destination dir %s can't be made: %d/%s\n",
				dst, errno, strerror(errno));
			return 1;
		}
	}

	if (output_name)
		snprintf(dst + len, dstlen - len, "%s.blktrace.%d",
			 output_name, cpu);
	else
		snprintf(dst + len, dstlen - len, "%s.blktrace.%d",
			 buts_name, cpu);

	return 0;
}

static int set_vbuf(struct io_info *iop, int mode, size_t size)
{
	iop->obuf = malloc(size);
	if (setvbuf(iop->ofp, iop->obuf, mode, size) < 0) {
		fprintf(stderr, "setvbuf(%s, %d) failed: %d/%s\n",
			iop->dpp->path, (int)size, errno,
			strerror(errno));
		free(iop->obuf);
		return 1;
	}

	return 0;
}

static int iop_open(struct io_info *iop, int cpu)
{
	char hostdir[MAXPATHLEN + 64];

	iop->ofd = -1;
	if (net_mode == Net_server) {
		struct cl_conn *nc = iop->nc;
		int len;

		len = snprintf(hostdir, sizeof(hostdir), "%s-",
			       nc->ch->hostname);
		len += strftime(hostdir + len, sizeof(hostdir) - len, "%F-%T/",
				gmtime(&iop->dpp->cl_connect_time));
	} else {
		hostdir[0] = 0;
	}

	if (fill_ofname(iop->ofn, sizeof(iop->ofn), hostdir,
			iop->dpp->buts_name, cpu))
		return 1;

	iop->ofp = my_fopen(iop->ofn, "w+");
	if (iop->ofp == NULL) {
		fprintf(stderr, "Open output file %s failed: %d/%s\n",
			iop->ofn, errno, strerror(errno));
		return 1;
	}

	if (set_vbuf(iop, _IOLBF, FILE_VBUF_SIZE)) {
		fprintf(stderr, "set_vbuf for file %s failed: %d/%s\n",
			iop->ofn, errno, strerror(errno));
		fclose(iop->ofp);
		return 1;
	}

	iop->ofd = fileno(iop->ofp);
	return 0;
}

static void close_iop(struct io_info *iop)
{
	struct mmap_info *mip = &iop->mmap_info;

	if (mip->fs_buf)
		munmap(mip->fs_buf, mip->fs_buf_len);

	if (!piped_output) {
		if (ftruncate(fileno(iop->ofp), mip->fs_size) < 0) {
			fprintf(stderr,
				"Ignoring err: ftruncate(%s): %d/%s\n",
				iop->ofn, errno, strerror(errno));
		}
	}

	if (iop->ofp)
		fclose(iop->ofp);
	if (iop->obuf)
		free(iop->obuf);
}

static void close_ios(struct tracer *tp)
{
	while (tp->nios > 0) {
		struct io_info *iop = &tp->ios[--tp->nios];

		iop->dpp->drops = get_drops(iop->dpp);
		if (iop->ifd >= 0)
			close(iop->ifd);

		if (iop->ofp)
			close_iop(iop);
		else if (iop->ofd >= 0) {
			struct devpath *dpp = iop->dpp;

			net_send_close(iop->ofd, dpp->buts_name, dpp->drops);
			net_close_connection(&iop->ofd);
		}
	}

	free(tp->ios);
	free(tp->pfds);
}

static int open_ios(struct tracer *tp)
{
	struct pollfd *pfd;
	struct io_info *iop;
	struct list_head *p;

	tp->ios = calloc(ndevs, sizeof(struct io_info));
	memset(tp->ios, 0, ndevs * sizeof(struct io_info));

	tp->pfds = calloc(ndevs, sizeof(struct pollfd));
	memset(tp->pfds, 0, ndevs * sizeof(struct pollfd));

	tp->nios = 0;
	iop = tp->ios;
	pfd = tp->pfds;
	__list_for_each(p, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);

		iop->dpp = dpp;
		iop->ofd = -1;
		snprintf(iop->ifn, sizeof(iop->ifn), "%s/block/%s/trace%d",
			debugfs_path, dpp->buts_name, tp->cpu);

		iop->ifd = my_open(iop->ifn, O_RDONLY | O_NONBLOCK);
		if (iop->ifd < 0) {
			fprintf(stderr, "Thread %d failed open %s: %d/%s\n",
				tp->cpu, iop->ifn, errno, strerror(errno));
			return 1;
		}

		init_mmap_info(&iop->mmap_info);

		pfd->fd = iop->ifd;
		pfd->events = POLLIN;

		if (piped_output)
			;
		else if (net_client_use_sendfile()) {
			iop->ofd = net_setup_client();
			if (iop->ofd < 0)
				goto err;
			net_send_open(iop->ofd, tp->cpu, dpp->buts_name);
		} else if (net_mode == Net_none) {
			if (iop_open(iop, tp->cpu))
				goto err;
		} else {
			/*
			 * This ensures that the server knows about all
			 * connections & devices before _any_ closes
			 */
			net_send_open(cl_fds[tp->cpu], tp->cpu, dpp->buts_name);
		}

		pfd++;
		iop++;
		tp->nios++;
	}

	return 0;

err:
	close(iop->ifd);	/* tp->nios _not_ bumped */
	close_ios(tp);
	return 1;
}

static int handle_pfds_file(struct tracer *tp, int nevs, int force_read)
{
	struct mmap_info *mip;
	int i, ret, nentries = 0;
	struct pollfd *pfd = tp->pfds;
	struct io_info *iop = tp->ios;

	for (i = 0; nevs > 0 && i < ndevs; i++, pfd++, iop++) {
		if (pfd->revents & POLLIN || force_read) {
			mip = &iop->mmap_info;

			ret = setup_mmap(iop->ofd, buf_size, mip, tp);
			if (ret < 0) {
				pfd->events = 0;
				break;
			}

			ret = read(iop->ifd, mip->fs_buf + mip->fs_off,
				   buf_size);
			if (ret > 0) {
				pdc_dr_update(iop->dpp, tp->cpu, ret);
				mip->fs_size += ret;
				mip->fs_off += ret;
				nentries++;
			} else if (ret == 0) {
				/*
				 * Short reads after we're done stop us
				 * from trying reads.
				 */
				if (tp->is_done)
					clear_events(pfd);
			} else {
				read_err(tp->cpu, iop->ifn);
				if (errno != EAGAIN || tp->is_done)
					clear_events(pfd);
			}
			nevs--;
		}
	}

	return nentries;
}

static int handle_pfds_netclient(struct tracer *tp, int nevs, int force_read)
{
	struct stat sb;
	int i, nentries = 0;
	struct pollfd *pfd = tp->pfds;
	struct io_info *iop = tp->ios;

	for (i = 0; i < ndevs; i++, pfd++, iop++) {
		if (pfd->revents & POLLIN || force_read) {
			if (fstat(iop->ifd, &sb) < 0) {
				perror(iop->ifn);
				pfd->events = 0;
			} else if (sb.st_size > (off_t)iop->data_queued) {
				iop->ready = sb.st_size - iop->data_queued;
				iop->data_queued = sb.st_size;

				if (!net_sendfile_data(tp, iop)) {
					pdc_dr_update(iop->dpp, tp->cpu,
						      iop->ready);
					nentries++;
				} else
					clear_events(pfd);
			}
			if (--nevs == 0)
				break;
		}
	}

	if (nentries)
		incr_entries(nentries);

	return nentries;
}

static int handle_pfds_entries(struct tracer *tp, int nevs, int force_read)
{
	int i, nentries = 0;
	struct trace_buf *tbp;
	struct pollfd *pfd = tp->pfds;
	struct io_info *iop = tp->ios;

	tbp = alloc_trace_buf(tp->cpu, buf_size);
	for (i = 0; i < ndevs; i++, pfd++, iop++) {
		if (pfd->revents & POLLIN || force_read) {
			tbp->len = read(iop->ifd, tbp->buf, buf_size);
			if (tbp->len > 0) {
				pdc_dr_update(iop->dpp, tp->cpu, tbp->len);
				add_trace_buf(iop->dpp, tp->cpu, &tbp);
				nentries++;
			} else if (tbp->len == 0) {
				/*
				 * Short reads after we're done stop us
				 * from trying reads.
				 */
				if (tp->is_done)
					clear_events(pfd);
			} else {
				read_err(tp->cpu, iop->ifn);
				if (errno != EAGAIN || tp->is_done)
					clear_events(pfd);
			}
			if (!piped_output && --nevs == 0)
				break;
		}
	}
	free(tbp);

	if (nentries)
		incr_entries(nentries);

	return nentries;
}

static void *thread_main(void *arg)
{
	int ret, ndone, to_val;
	struct tracer *tp = arg;

	ret = lock_on_cpu(tp->cpu);
	if (ret)
		goto err;

	ret = open_ios(tp);
	if (ret)
		goto err;

	if (piped_output)
		to_val = 50;		/* Frequent partial handles */
	else
		to_val = 500;		/* 1/2 second intervals */


	tracer_signal_ready(tp, Th_running, 0);
	tracer_wait_unblock(tp);

	while (!tp->is_done) {
		ndone = poll(tp->pfds, ndevs, to_val);
		if (ndone || piped_output)
			(void)handle_pfds(tp, ndone, piped_output);
		else if (ndone < 0 && errno != EINTR)
			fprintf(stderr, "Thread %d poll failed: %d/%s\n",
				tp->cpu, errno, strerror(errno));
	}

	/*
	 * Trace is stopped, pull data until we get a short read
	 */
	while (handle_pfds(tp, ndevs, 1) > 0)
		;

	close_ios(tp);
	tracer_signal_ready(tp, Th_leaving, 0);
	return NULL;

err:
	tracer_signal_ready(tp, Th_error, ret);
	return NULL;
}

static int start_tracer(int cpu)
{
	struct tracer *tp;

	tp = malloc(sizeof(*tp));
	memset(tp, 0, sizeof(*tp));

	INIT_LIST_HEAD(&tp->head);
	tp->status = 0;
	tp->cpu = cpu;

	if (pthread_create(&tp->thread, NULL, thread_main, tp)) {
		fprintf(stderr, "FAILED to start thread on CPU %d: %d/%s\n",
			cpu, errno, strerror(errno));
		free(tp);
		return 1;
	}

	list_add_tail(&tp->head, &tracers);
	return 0;
}

static int create_output_files(int cpu)
{
	char fname[MAXPATHLEN + 64];
	struct list_head *p;
	FILE *f;

	__list_for_each(p, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);

		if (fill_ofname(fname, sizeof(fname), NULL, dpp->buts_name,
				cpu))
			return 1;
		f = my_fopen(fname, "w+");
		if (!f)
			return 1;
		fclose(f);
	}
	return 0;
}

static void start_tracers(void)
{
	int cpu, started = 0;
	struct list_head *p;
	size_t alloc_size = CPU_ALLOC_SIZE(max_cpus);

	for (cpu = 0; cpu < max_cpus; cpu++) {
		if (!CPU_ISSET_S(cpu, alloc_size, online_cpus)) {
			/*
			 * Create fake empty output files so that other tools
			 * like blkparse don't have to bother with sparse CPU
			 * number space.
			 */
			if (create_output_files(cpu))
				break;
			continue;
		}
		if (start_tracer(cpu))
			break;
		started++;
	}

	wait_tracers_ready(started);

	__list_for_each(p, &tracers) {
		struct tracer *tp = list_entry(p, struct tracer, head);
		if (tp->status)
			fprintf(stderr,
				"FAILED to start thread on CPU %d: %d/%s\n",
				tp->cpu, tp->status, strerror(tp->status));
	}
}

static void stop_tracers(void)
{
	struct list_head *p;

	/*
	 * Stop the tracing - makes the tracer threads clean up quicker.
	 */
	__list_for_each(p, &devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);
		(void)ioctl(dpp->fd, BLKTRACESTOP);
	}

	/*
	 * Tell each tracer to quit
	 */
	__list_for_each(p, &tracers) {
		struct tracer *tp = list_entry(p, struct tracer, head);
		tp->is_done = 1;
	}
	pthread_cond_broadcast(&mt_cond);
}

static void del_tracers(void)
{
	struct list_head *p, *q;

	list_for_each_safe(p, q, &tracers) {
		struct tracer *tp = list_entry(p, struct tracer, head);

		list_del(&tp->head);
		free(tp);
	}
}

static void wait_tracers(void)
{
	struct list_head *p;

	if (use_tracer_devpaths())
		process_trace_bufs();

	wait_tracers_leaving();

	__list_for_each(p, &tracers) {
		int ret;
		struct tracer *tp = list_entry(p, struct tracer, head);

		ret = pthread_join(tp->thread, NULL);
		if (ret)
			fprintf(stderr, "Thread join %d failed %d\n",
				tp->cpu, ret);
	}

	if (use_tracer_devpaths())
		clean_trace_bufs();

	get_all_drops();
}

static void exit_tracing(void)
{
	signal(SIGINT, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGALRM, SIG_IGN);

	stop_tracers();
	wait_tracers();
	del_tracers();
	rel_devpaths();
}

static void handle_sigint(__attribute__((__unused__)) int sig)
{
	done = 1;
	stop_tracers();
}

#ifdef RBLKTRACE
static const char *rbt_client_hostname(struct devpath *dpp);
static size_t rbt_header_reads(struct devpath *dpp, int cpu);
static size_t rbt_data_reads(struct devpath *dpp, int cpu);
#endif

static void show_stats(struct list_head *devpaths)
{
	FILE *ofp;
	struct list_head *p;
	unsigned long long nevents, data_read;
	unsigned long long total_drops = 0;
	unsigned long long total_events = 0;

	if (piped_output)
		ofp = my_fopen("/dev/null", "w");
	else
		ofp = stdout;

	__list_for_each(p, devpaths) {
		int cpu;
		struct pdc_stats *sp;
		struct devpath *dpp = list_entry(p, struct devpath, head);

		if (net_mode == Net_server)
			printf("server: end of run for %s:%s\n",
				dpp->ch->hostname, dpp->buts_name);
#ifdef RBLKTRACE
		if (net_mode == Net_server_rdma) {
			printf("rdma server: end of run for %s:%s\n", rbt_client_hostname(dpp), dpp->buts_name);
		}
#endif

		data_read = 0;
		nevents = 0;
#ifdef RBLKTRACE
		size_t header_reads = 0;
		size_t data_reads = 0;
#endif

		fprintf(ofp, "=== %s ===\n", dpp->buts_name);
		for (cpu = 0, sp = dpp->stats; cpu < dpp->ncpus; cpu++, sp++) {
			/*
			 * Estimate events if not known...
			 */
			if (sp->nevents == 0) {
				sp->nevents = sp->data_read /
						sizeof(struct blk_io_trace);
			}

			fprintf(ofp,
				"  CPU%3d: %20llu events, %8llu KiB data\n",
				cpu, sp->nevents, (sp->data_read + 1023) >> 10);

			data_read += sp->data_read;
			nevents += sp->nevents;

#ifdef RBLKTRACE
			if (net_mode == Net_server_rdma) {
				fprintf(ofp, "      %zu header reads, %zu data reads\n",
				        rbt_header_reads(dpp, cpu), rbt_data_reads(dpp, cpu));
				header_reads += rbt_header_reads(dpp, cpu);
				data_reads += rbt_data_reads(dpp, cpu);
			}
#endif
		}

		fprintf(ofp, "  Total:  %20llu events (dropped %llu),"
			     " %8llu KiB data\n", nevents,
			     dpp->drops, (data_read + 1023) >> 10);

#ifdef RBLKTRACE
		if (net_mode == Net_server_rdma) {
			fprintf(ofp, "      %zu header reads, %zu data reads\n", header_reads, data_reads);
		}
#endif

		total_drops += dpp->drops;
		total_events += (nevents + dpp->drops);
	}

	fflush(ofp);
	if (piped_output)
		fclose(ofp);

	if (total_drops) {
		double drops_ratio = 1.0;

		if (total_events)
			drops_ratio = (double)total_drops/(double)total_events;

		fprintf(stderr, "\nYou have %llu (%5.1lf%%) dropped events\n"
				"Consider using a larger buffer size (-b) "
				"and/or more buffers (-n)\n",
			total_drops, 100.0 * drops_ratio);
	}
}

static int handle_args(int argc, char *argv[])
{
	int c, i;
	struct statfs st;
	int act_mask_tmp = 0;

#ifdef RBLKTRACE
	bool buf_nr_set = false;
#endif

	while ((c = getopt_long(argc, argv, S_OPTS, l_opts, NULL)) >= 0) {
		switch (c) {
		case 'a':
			i = find_mask_map(optarg);
			if (i < 0) {
				fprintf(stderr, "Invalid action mask %s\n",
					optarg);
				return 1;
			}
			act_mask_tmp |= i;
			break;

		case 'A':
			if ((sscanf(optarg, "%x", &i) != 1) ||
							!valid_act_opt(i)) {
				fprintf(stderr,
					"Invalid set action mask %s/0x%x\n",
					optarg, i);
				return 1;
			}
			act_mask_tmp = i;
			break;

		case 'd':
			if (add_devpath(optarg) != 0)
				return 1;
			break;

		case 'I': {
			char dev_line[256];
			FILE *ifp = my_fopen(optarg, "r");

			if (!ifp) {
				fprintf(stderr,
					"Invalid file for devices %s\n",
					optarg);
				return 1;
			}

			while (fscanf(ifp, "%s\n", dev_line) == 1) {
				if (add_devpath(dev_line) != 0) {
					fclose(ifp);
					return 1;
				}
			}
			fclose(ifp);
			break;
		}

		case 'r':
			debugfs_path = optarg;
			break;

		case 'o':
			output_name = optarg;
			break;
		case 'k':
			kill_running_trace = 1;
			break;
		case 'w':
			stop_watch = atoi(optarg);
			if (stop_watch <= 0) {
				fprintf(stderr,
					"Invalid stopwatch value (%d secs)\n",
					stop_watch);
				return 1;
			}
			break;
		case 'V':
		case 'v':
			printf("%s version %s\n", argv[0], blktrace_version);
			exit(0);
			/*NOTREACHED*/
		case 'b':
			buf_size = strtoul(optarg, NULL, 10);
			if (buf_size <= 0 || buf_size > 16*1024) {
				fprintf(stderr, "Invalid buffer size (%lu)\n",
					buf_size);
				return 1;
			}
			buf_size <<= 10;
			break;
		case 'n':
			buf_nr = strtoul(optarg, NULL, 10);
			if (buf_nr <= 0) {
				fprintf(stderr,
					"Invalid buffer nr (%lu)\n", buf_nr);
				return 1;
			}
#ifdef RBLKTRACE
			buf_nr_set = true;
#endif
			break;
		case 'D':
			output_dir = optarg;
			break;
		case 'h':
			net_mode = Net_client;
			memset(hostname, 0, sizeof(hostname));
			strncpy(hostname, optarg, sizeof(hostname));
			hostname[sizeof(hostname) - 1] = '\0';
			break;
		case 'l':
			net_mode = Net_server;
			break;
		case 'p':
			net_port = atoi(optarg);
			break;
		case 's':
			net_use_sendfile = 0;
			break;

#ifdef RBLKTRACE
		case 'R':
			use_rdma = true;
			break;
		case 'm':
			if ((max_ncpus = atoi(optarg)) <= 0) {
				fprintf(stderr, "Invalid maximum number of client CPUs (%s)\n", optarg);
				return 1;
			}
			break;
		case 'M':
			if ((max_ndevs = atoi(optarg)) <= 0) {
				fprintf(stderr, "Invalid maximum number of client devices (%s)\n", optarg);
				return 1;
			}
			break;
		case 'i':
			if ((rdma_interval = atoi(optarg)) <= 0) {
				fprintf(stderr, "Invalid RDMA read interval (%s)\n", optarg);
				return 1;
			}
			break;
#endif// RBLKTRACE

		default:
			show_usage(argv[0]);
			exit(1);
			/*NOTREACHED*/
		}
	}

#ifdef RBLKTRACE
	if (use_rdma) {
		switch (net_mode) {
			case Net_server: net_mode = Net_server_rdma; break;
			case Net_client: net_mode = Net_client_rdma; break;
		}

		if ((net_port < 0) || (net_port > USHRT_MAX)) {
			fprintf(stderr, "Invalid RDMA port: %d\n", net_port);
		}
		snprintf(rdma_port, sizeof(rdma_port), "%d", net_port);
	}

	// Need more sub-buffers to mitigate delays due to on-demand memory registration on the server
	if ((net_mode == Net_client_rdma) && !buf_nr_set) buf_nr = 16;
#endif// RBLKTRACE

	while (optind < argc)
		if (add_devpath(argv[optind++]) != 0)
			return 1;

#ifdef RBLKTRACE
	if (net_mode != Net_server && net_mode != Net_server_rdma && ndevs == 0)
#else
	if (net_mode != Net_server && ndevs == 0)
#endif
	{
		show_usage(argv[0]);
		return 1;
	}

	if (statfs(debugfs_path, &st) < 0) {
		fprintf(stderr, "Invalid debug path %s: %d/%s\n",
			debugfs_path, errno, strerror(errno));
		return 1;
	}

	if (st.f_type != (long)DEBUGFS_TYPE) {
		fprintf(stderr, "Debugfs is not mounted at %s\n", debugfs_path);
		return 1;
	}

	if (act_mask_tmp != 0)
		act_mask = act_mask_tmp;

	if (net_mode == Net_client && net_setup_addr())
		return 1;

	/*
	 * Set up for appropriate PFD handler based upon output name.
	 */
	if (net_client_use_sendfile())
		handle_pfds = handle_pfds_netclient;
	else if (net_client_use_send())
		handle_pfds = handle_pfds_entries;
	else if (output_name && (strcmp(output_name, "-") == 0)) {
		piped_output = 1;
		handle_pfds = handle_pfds_entries;
		pfp = stdout;
		if (setvbuf(pfp, NULL, _IONBF, 0)) {
			perror("setvbuf stdout");
			return 1;
		}
	} else
		handle_pfds = handle_pfds_file;
	return 0;
}

static void ch_add_connection(struct net_server_s *ns, struct cl_host *ch,
			      int fd)
{
	struct cl_conn *nc;

	nc = malloc(sizeof(*nc));
	memset(nc, 0, sizeof(*nc));

	time(&nc->connect_time);
	nc->ch = ch;
	nc->fd = fd;
	nc->ncpus = -1;

	list_add_tail(&nc->ch_head, &ch->conn_list);
	ch->connects++;

	list_add_tail(&nc->ns_head, &ns->conn_list);
	ns->connects++;
	ns->pfds = realloc(ns->pfds, (ns->connects+1) * sizeof(struct pollfd));
}

static void ch_rem_connection(struct net_server_s *ns, struct cl_host *ch,
			      struct cl_conn *nc)
{
	net_close_connection(&nc->fd);

	list_del(&nc->ch_head);
	ch->connects--;

	list_del(&nc->ns_head);
	ns->connects--;
	ns->pfds = realloc(ns->pfds, (ns->connects+1) * sizeof(struct pollfd));

	free(nc);
}

static struct cl_host *net_find_client_host(struct net_server_s *ns,
					    struct in_addr cl_in_addr)
{
	struct list_head *p;

	__list_for_each(p, &ns->ch_list) {
		struct cl_host *ch = list_entry(p, struct cl_host, head);

		if (in_addr_eq(ch->cl_in_addr, cl_in_addr))
			return ch;
	}

	return NULL;
}

static struct cl_host *net_add_client_host(struct net_server_s *ns,
					   struct sockaddr_in *addr)
{
	struct cl_host *ch;

	ch = malloc(sizeof(*ch));
	memset(ch, 0, sizeof(*ch));

	ch->ns = ns;
	ch->cl_in_addr = addr->sin_addr;
	list_add_tail(&ch->head, &ns->ch_list);
	ns->nchs++;

	ch->hostname = strdup(inet_ntoa(addr->sin_addr));
	printf("server: connection from %s\n", ch->hostname);

	INIT_LIST_HEAD(&ch->conn_list);
	INIT_LIST_HEAD(&ch->devpaths);

	return ch;
}

static void device_done(struct devpath *dpp, int ncpus)
{
	int cpu;
	struct io_info *iop;

	for (cpu = 0, iop = dpp->ios; cpu < ncpus; cpu++, iop++)
		close_iop(iop);

	list_del(&dpp->head);
	dpp_free(dpp);
}

static void net_ch_remove(struct cl_host *ch, int ncpus)
{
	struct list_head *p, *q;
	struct net_server_s *ns = ch->ns;

	list_for_each_safe(p, q, &ch->devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);
		device_done(dpp, ncpus);
	}

	list_for_each_safe(p, q, &ch->conn_list) {
		struct cl_conn *nc = list_entry(p, struct cl_conn, ch_head);

		ch_rem_connection(ns, ch, nc);
	}

	list_del(&ch->head);
	ns->nchs--;

	if (ch->hostname)
		free(ch->hostname);
	free(ch);
}

static void net_add_connection(struct net_server_s *ns)
{
	int fd;
	struct cl_host *ch;
	socklen_t socklen = sizeof(ns->addr);

	fd = my_accept(ns->listen_fd, (struct sockaddr *)&ns->addr, &socklen);
	if (fd < 0) {
		/*
		 * This is OK: we just won't accept this connection,
		 * nothing fatal.
		 */
		perror("accept");
	} else {
		ch = net_find_client_host(ns, ns->addr.sin_addr);
		if (!ch)
			ch = net_add_client_host(ns, &ns->addr);

		ch_add_connection(ns, ch, fd);
	}
}

static struct devpath *nc_add_dpp(struct cl_conn *nc,
				  struct blktrace_net_hdr *bnh,
				  time_t connect_time)
{
	int cpu;
	struct io_info *iop;
	struct devpath *dpp;

	dpp = malloc(sizeof(*dpp));
	memset(dpp, 0, sizeof(*dpp));

	dpp->buts_name = strdup(bnh->buts_name);
	dpp->path = strdup(bnh->buts_name);
	dpp->fd = -1;
	dpp->ch = nc->ch;
	dpp->cl_id = bnh->cl_id;
	dpp->cl_connect_time = connect_time;
	dpp->ncpus = nc->ncpus;
	dpp->stats = calloc(dpp->ncpus, sizeof(*dpp->stats));
	memset(dpp->stats, 0, dpp->ncpus * sizeof(*dpp->stats));

	list_add_tail(&dpp->head, &nc->ch->devpaths);
	nc->ch->ndevs++;

	dpp->ios = calloc(nc->ncpus, sizeof(*iop));
	memset(dpp->ios, 0, ndevs * sizeof(*iop));

	for (cpu = 0, iop = dpp->ios; cpu < nc->ncpus; cpu++, iop++) {
		iop->dpp = dpp;
		iop->nc = nc;
		init_mmap_info(&iop->mmap_info);

		if (iop_open(iop, cpu))
			goto err;
	}

	return dpp;

err:
	/*
	 * Need to unravel what's been done...
	 */
	while (cpu >= 0)
		close_iop(&dpp->ios[cpu--]);
	dpp_free(dpp);

	return NULL;
}

static struct devpath *nc_find_dpp(struct cl_conn *nc,
				   struct blktrace_net_hdr *bnh)
{
	struct list_head *p;
	time_t connect_time = nc->connect_time;

	__list_for_each(p, &nc->ch->devpaths) {
		struct devpath *dpp = list_entry(p, struct devpath, head);

		if (!strcmp(dpp->buts_name, bnh->buts_name))
			return dpp;

		if (dpp->cl_id == bnh->cl_id)
			connect_time = dpp->cl_connect_time;
	}

	return nc_add_dpp(nc, bnh, connect_time);
}

static void net_client_read_data(struct cl_conn *nc, struct devpath *dpp,
				 struct blktrace_net_hdr *bnh)
{
	int ret;
	struct io_info *iop = &dpp->ios[bnh->cpu];
	struct mmap_info *mip = &iop->mmap_info;

	if (setup_mmap(iop->ofd, bnh->len, &iop->mmap_info, NULL)) {
		fprintf(stderr, "ncd(%s:%d): mmap failed\n",
			nc->ch->hostname, nc->fd);
		exit(1);
	}

	ret = net_recv_data(nc->fd, mip->fs_buf + mip->fs_off, bnh->len);
	if (ret > 0) {
		pdc_dr_update(dpp, bnh->cpu, ret);
		mip->fs_size += ret;
		mip->fs_off += ret;
	} else if (ret < 0)
		exit(1);
}

/*
 * Returns 1 if we closed a host - invalidates other polling information
 * that may be present.
 */
static int net_client_data(struct cl_conn *nc)
{
	int ret;
	struct devpath *dpp;
	struct blktrace_net_hdr bnh;

	ret = net_get_header(nc, &bnh);
	if (ret == 0)
		return 0;

	if (ret < 0) {
		fprintf(stderr, "ncd(%d): header read failed\n", nc->fd);
		exit(1);
	}

	if (data_is_native == -1 && check_data_endianness(bnh.magic)) {
		fprintf(stderr, "ncd(%d): received data is bad\n", nc->fd);
		exit(1);
	}

	if (!data_is_native) {
		bnh.magic = be32_to_cpu(bnh.magic);
		bnh.cpu = be32_to_cpu(bnh.cpu);
		bnh.max_cpus = be32_to_cpu(bnh.max_cpus);
		bnh.len = be32_to_cpu(bnh.len);
		bnh.cl_id = be32_to_cpu(bnh.cl_id);
		bnh.buf_size = be32_to_cpu(bnh.buf_size);
		bnh.buf_nr = be32_to_cpu(bnh.buf_nr);
		bnh.page_size = be32_to_cpu(bnh.page_size);
	}

	if ((bnh.magic & 0xffffff00) != BLK_IO_TRACE_MAGIC) {
		fprintf(stderr, "ncd(%s:%d): bad data magic\n",
			nc->ch->hostname, nc->fd);
		exit(1);
	}

	if (nc->ncpus == -1)
		nc->ncpus = bnh.max_cpus;

	/*
	 * len == 0 means the other end is sending us a new connection/dpp
	 * len == 1 means that the other end signalled end-of-run
	 */
	dpp = nc_find_dpp(nc, &bnh);
	if (bnh.len == 0) {
		/*
		 * Just adding in the dpp above is enough
		 */
		ack_open_close(nc->fd, dpp->buts_name);
		nc->ch->cl_opens++;
	} else if (bnh.len == 1) {
		/*
		 * overload cpu count with dropped events
		 */
		dpp->drops = bnh.cpu;

		ack_open_close(nc->fd, dpp->buts_name);
		if (--nc->ch->cl_opens == 0) {
			show_stats(&nc->ch->devpaths);
			net_ch_remove(nc->ch, nc->ncpus);
			return 1;
		}
	} else
		net_client_read_data(nc, dpp, &bnh);

	return 0;
}

static void handle_client_data(struct net_server_s *ns, int events)
{
	struct cl_conn *nc;
	struct pollfd *pfd;
	struct list_head *p, *q;

	pfd = &ns->pfds[1];
	list_for_each_safe(p, q, &ns->conn_list) {
		if (pfd->revents & POLLIN) {
			nc = list_entry(p, struct cl_conn, ns_head);

			if (net_client_data(nc) || --events == 0)
				break;
		}
		pfd++;
	}
}

static void net_setup_pfds(struct net_server_s *ns)
{
	struct pollfd *pfd;
	struct list_head *p;

	ns->pfds[0].fd = ns->listen_fd;
	ns->pfds[0].events = POLLIN;

	pfd = &ns->pfds[1];
	__list_for_each(p, &ns->conn_list) {
		struct cl_conn *nc = list_entry(p, struct cl_conn, ns_head);

		pfd->fd = nc->fd;
		pfd->events = POLLIN;
		pfd++;
	}
}

static int net_server_handle_connections(struct net_server_s *ns)
{
	int events;

	printf("server: waiting for connections...\n");

	while (!done) {
		net_setup_pfds(ns);
		events = poll(ns->pfds, ns->connects + 1, -1);
		if (events < 0) {
			if (errno != EINTR) {
				perror("FATAL: poll error");
				return 1;
			}
		} else if (events > 0) {
			if (ns->pfds[0].revents & POLLIN) {
				net_add_connection(ns);
				events--;
			}

			if (events)
				handle_client_data(ns, events);
		}
	}

	return 0;
}

static int net_server(void)
{
	int fd, opt;
	int ret = 1;
	struct net_server_s net_server;
	struct net_server_s *ns = &net_server;

	memset(ns, 0, sizeof(*ns));
	INIT_LIST_HEAD(&ns->ch_list);
	INIT_LIST_HEAD(&ns->conn_list);
	ns->pfds = malloc(sizeof(struct pollfd));

	fd = my_socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("server: socket");
		goto out;
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt");
		goto out;
	}

	memset(&ns->addr, 0, sizeof(ns->addr));
	ns->addr.sin_family = AF_INET;
	ns->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ns->addr.sin_port = htons(net_port);

	if (bind(fd, (struct sockaddr *) &ns->addr, sizeof(ns->addr)) < 0) {
		perror("bind");
		goto out;
	}

	if (listen(fd, 1) < 0) {
		perror("listen");
		goto out;
	}

	/*
	 * The actual server looping is done here:
	 */
	ns->listen_fd = fd;
	ret = net_server_handle_connections(ns);

	/*
	 * Clean up and return...
	 */
out:
	free(ns->pfds);
	return ret;
}

static int run_tracers(void)
{
	atexit(exit_tracing);
	if (net_mode == Net_client)
		printf("blktrace: connecting to %s\n", hostname);

	if (setup_buts())
		return 1;

	if (use_tracer_devpaths()) {
		if (setup_tracer_devpaths())
			return 1;

		if (piped_output)
			handle_list = handle_list_file;
		else
			handle_list = handle_list_net;
	}

	start_tracers();
	if (nthreads_running == ncpus) {
		unblock_tracers();
		start_buts();
		if (net_mode == Net_client)
			printf("blktrace: connected!\n");
		if (stop_watch)
			alarm(stop_watch);
	} else
		stop_tracers();

	wait_tracers();
	if (nthreads_running == ncpus)
		show_stats(&devpaths);
	if (net_client_use_send())
		close_client_connections();
	del_tracers();

	return 0;
}

static cpu_set_t *get_online_cpus(void)
{
	FILE *cpus;
	cpu_set_t *set;
	size_t alloc_size;
	int cpuid, prevcpuid = -1;
	char nextch;
	int n, ncpu, curcpu = 0;
	int *cpu_nums;

	ncpu = sysconf(_SC_NPROCESSORS_CONF);
	if (ncpu < 0)
		return NULL;

	cpu_nums = malloc(sizeof(int)*ncpu);
	if (!cpu_nums) {
		errno = ENOMEM;
		return NULL;
	}

	/*
	 * There is no way to easily get maximum CPU number. So we have to
	 * parse the file first to find it out and then create appropriate
	 * cpuset
	 */
	cpus = my_fopen("/sys/devices/system/cpu/online", "r");
	for (;;) {
		n = fscanf(cpus, "%d%c", &cpuid, &nextch);
		if (n <= 0)
			break;
		if (n == 2 && nextch == '-') {
			prevcpuid = cpuid;
			continue;
		}
		if (prevcpuid == -1)
			prevcpuid = cpuid;
		while (prevcpuid <= cpuid) {
			/* More CPUs listed than configured? */
			if (curcpu >= ncpu) {
				errno = EINVAL;
				return NULL;
			}
			cpu_nums[curcpu++] = prevcpuid++;
		}
		prevcpuid = -1;
	}
	fclose(cpus);

	ncpu = curcpu;
	max_cpus = cpu_nums[ncpu - 1] + 1;

	/* Now that we have maximum cpu number, create a cpuset */
	set = CPU_ALLOC(max_cpus);
	if (!set) {
		errno = ENOMEM;
		return NULL;
	}
	alloc_size = CPU_ALLOC_SIZE(max_cpus);
	CPU_ZERO_S(alloc_size, set);

	for (curcpu = 0; curcpu < ncpu; curcpu++)
		CPU_SET_S(cpu_nums[curcpu], alloc_size, set);

	free(cpu_nums);

	return set;
}

#ifdef RBLKTRACE
static int net_client_rdma(void);
static int net_server_rdma(void);
#endif

int main(int argc, char *argv[])
{
	int ret = 0;

	setlocale(LC_NUMERIC, "en_US");
	pagesize = getpagesize();
	online_cpus = get_online_cpus();
	if (!online_cpus) {
		fprintf(stderr, "cannot get online cpus %d/%s\n",
			errno, strerror(errno));
		ret = 1;
		goto out;
	} else if (handle_args(argc, argv)) {
		ret = 1;
		goto out;
	}

	ncpus = CPU_COUNT_S(CPU_ALLOC_SIZE(max_cpus), online_cpus);
	if (ndevs > 1 && output_name && strcmp(output_name, "-") != 0) {
		fprintf(stderr, "-o not supported with multiple devices\n");
		ret = 1;
		goto out;
	}

	signal(SIGINT, handle_sigint);
	signal(SIGHUP, handle_sigint);
	signal(SIGTERM, handle_sigint);
	signal(SIGALRM, handle_sigint);
	signal(SIGPIPE, SIG_IGN);

	if (kill_running_trace) {
		struct devpath *dpp;
		struct list_head *p;

		__list_for_each(p, &devpaths) {
			dpp = list_entry(p, struct devpath, head);
			if (__stop_trace(dpp->fd)) {
				fprintf(stderr,
					"BLKTRACETEARDOWN %s failed: %d/%s\n",
					dpp->path, errno, strerror(errno));
			}
		}
	} else if (net_mode == Net_server) {
		if (output_name) {
			fprintf(stderr, "-o ignored in server mode\n");
			output_name = NULL;
		}
		ret = net_server();
#ifdef RBLKTRACE
	} else if (net_mode == Net_server_rdma) {
		if (output_name) {
			fprintf(stderr, "-o ignored in server mode\n");
			output_name = NULL;
		}
		ret = net_server_rdma();
	} else if (net_mode == Net_client_rdma) {
		ret = net_client_rdma();
#endif// RBLKTRACE
	} else
		ret = run_tracers();

out:
	if (pfp)
		fclose(pfp);
	rel_devpaths();
	return ret;
}


#ifdef RBLKTRACE


//NOTE: we only support clients and servers with the same CPU architecture (word size and endianness)

typedef struct rbt_buf_info {
	void *addr;
	uint32_t read_rkey;
	uint32_t write_rkey;
} rbt_buf_info_t;


typedef struct rbt_dev_info {
	char buts_name[32];
	rbt_buf_info_t bufs[];
} rbt_dev_info_t;

static inline size_t rbt_dev_info_size(size_t ncpus)
{
	return sizeof(rbt_dev_info_t) + ncpus * sizeof(rbt_buf_info_t);
}


typedef struct rbt_open_req {
	uint32_t magic;
	int ndevs;
	int ncpus;
	int buf_size;
	int buf_nr;
	char data[];
} rbt_open_req_t;

static inline size_t rbt_open_req_size(size_t ndevs, size_t ncpus)
{
	return sizeof(rbt_open_req_t) + ndevs * rbt_dev_info_size(ncpus);
}

static inline rbt_dev_info_t *rbt_dev_info_at(rbt_open_req_t *req, int idx)
{
	assert(req != NULL);
	assert(idx < req->ndevs);
	return (rbt_dev_info_t*)(req->data + idx * rbt_dev_info_size(req->ncpus));
}


typedef struct rbt_open_resp {
	uint32_t magic;
	bool result;
} rbt_open_resp_t;


typedef struct rbt_close_req {
	uint32_t magic;
	unsigned long long drops[];
} rbt_close_req_t;

static inline size_t rbt_close_req_size(size_t ndevs)
{
	return sizeof(rbt_close_req_t) + ndevs * sizeof(unsigned long long);
}


typedef struct rbt_close_resp {
	uint32_t magic;
	unsigned long long data_read[];
} rbt_close_resp_t;

static inline size_t rbt_close_resp_size(size_t ndevs, size_t ncpus)
{
	return sizeof(rbt_close_resp_t) + ndevs * ncpus * sizeof(unsigned long long);
}

static inline unsigned long long *rbt_data_read_at(rbt_close_resp_t *resp, size_t ncpus, size_t dev_idx, size_t cpu_idx)
{
	assert(resp != NULL);
	assert(cpu_idx < ncpus);
	return &(resp->data_read[dev_idx * ncpus + cpu_idx]);
}


static void *my_malloc(size_t size)
{
	assert(size != 0);
	void *ptr = malloc(size);
	if (ptr == NULL) fprintf(stderr, "malloc(%zu): %s\n", size, strerror(errno));
	return ptr;
}

static void *my_calloc(size_t size)
{
	assert(size != 0);
	void *ptr = calloc(1, size);
	if (ptr == NULL) fprintf(stderr, "calloc(%zu): %s\n", size, strerror(errno));
	return ptr;
}

static void *my_realloc(void *old, size_t size)
{
	assert(size != 0);
	void *ptr = realloc(old, size);
	if (ptr == NULL) fprintf(stderr, "realloc(%zu): %s\n", size, strerror(errno));
	return ptr;
}

static char *my_strdup(const char *str)
{
	assert(str != NULL);
	char *s = strdup(str);
	if (s == NULL) perror("strdup");
	return s;
}


typedef struct rdma_cm_id rdma_cm_id_t;
typedef struct ibv_mr ibv_mr_t;

static ibv_mr_t *rbt_reg_msgs(rdma_cm_id_t *id, void *addr, size_t length)
{
	assert(id != NULL);
	assert(addr != NULL);

	ibv_mr_t *mr = rdma_reg_msgs(id, addr, length);
	if (mr == NULL) fprintf(stderr, "rdma_reg_msgs(%zu): %s\n", length, strerror(errno));
	return mr;
}

static ibv_mr_t *rbt_msg_buf_create(rdma_cm_id_t *id, size_t size)
{
	assert(id != NULL);

	void *buf = my_malloc(size);
	if (buf == NULL) return NULL;

	ibv_mr_t *mr = rbt_reg_msgs(id, buf, size);
	if (mr == NULL) free(buf);
	return mr;
}

static void rbt_msg_buf_destroy(ibv_mr_t *mr)
{
	assert(mr != NULL);
	void *buf = mr->addr;
	rdma_dereg_mr(mr);
	free(buf);
}


static bool rbt_post_send(rdma_cm_id_t *id, void *ctx, void *addr, size_t length, ibv_mr_t *mr, int flags)
{
	assert(id != NULL);
	assert(addr != NULL);

	if (rdma_post_send(id, ctx, addr, length, mr, flags) < 0) {
		perror("rdma_post_send");
		return false;
	}
	return true;
}

static bool rbt_post_recv(rdma_cm_id_t *id, void *ctx, void *addr, size_t length, ibv_mr_t *mr)
{
	assert(id != NULL);
	assert(addr != NULL);
	assert(mr != NULL);

	if (rdma_post_recv(id, ctx, addr, length, mr) < 0) {
		perror("rdma_post_recv");
		return false;
	}
	return true;
}


typedef struct ibv_wc ibv_wc_t;

static bool rbt_get_send_comp(rdma_cm_id_t *id, ibv_wc_t *wc)
{
	assert(id != NULL);
	assert(wc != NULL);

	int n = rdma_get_send_comp(id, wc);
	if (n < 0) {
		perror("rdma_get_send_comp");
		return false;
	}
	assert(n == 1);

	if (wc->status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Send request failed with %d\n", wc->status);
		return false;
	}
	assert(wc->opcode == IBV_WC_SEND);
	return true;
}

static bool rbt_get_recv_comp(rdma_cm_id_t *id, ibv_wc_t *wc)
{
	assert(id != NULL);
	assert(wc != NULL);

	int n = rdma_get_recv_comp(id, wc);
	if (n < 0) {
		perror("rdma_get_recv_comp");
		return false;
	}
	assert(n == 1);

	if (wc->status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Recv request failed with %d\n", wc->status);
		return false;
	}
	assert(wc->opcode == IBV_WC_RECV);
	return true;
}


static int rbt_get_fd_flags(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0) perror("fcntl");
	return flags;
}

static bool rbt_set_fd_flags(int fd, int flags)
{
	if (fcntl(fd, F_SETFL, flags) < 0) {
		perror("fcntl");
		return false;
	}
	return true;
}

static bool rbt_make_async(int fd)
{
	int flags = rbt_get_fd_flags(fd);
	return (flags >= 0) ? rbt_set_fd_flags(fd, flags | O_NONBLOCK) : false;
}

static bool rbt_make_sync(int fd)
{
	int flags = rbt_get_fd_flags(fd);
	return (flags >= 0) ? rbt_set_fd_flags(fd, flags & ~O_NONBLOCK) : false;
}


typedef struct ibv_cq ibv_cq_t;

static bool rbt_req_notify(ibv_cq_t *cq)
{
	assert(cq != NULL);

	if (rdma_seterrno(ibv_req_notify_cq(cq, 0)) < 0) {
		perror("ibv_req_notify_cq");
		return false;
	}
	return true;
}

static bool rbt_get_cq_event(rdma_cm_id_t *id, ibv_cq_t *id_cq, struct ibv_comp_channel *channel)
{
	ibv_cq_t *cq;
	void *ctx;
	if (ibv_get_cq_event(channel, &cq, &ctx) < 0) {
		perror("ibv_get_cq_event");
		return false;
	}

	assert(cq == id_cq);
	(void)id_cq;
	assert(ctx == id);
	(void)id;
	ibv_ack_cq_events(cq, 1);
	return true;
}

static bool rbt_get_send_cq_event(rdma_cm_id_t *id)
{
	assert(id != NULL);
	return rbt_get_cq_event(id, id->send_cq, id->send_cq_channel);
}

static bool rbt_get_recv_cq_event(rdma_cm_id_t *id)
{
	assert(id != NULL);
	return rbt_get_cq_event(id, id->recv_cq, id->recv_cq_channel);
}

static int rbt_poll_cq(ibv_cq_t *cq, ibv_wc_t *wc)
{
	assert(cq != NULL);
	assert(wc != NULL);

	int n = ibv_poll_cq(cq, 1, wc);
	if (n < 0) perror("ibv_poll_cq");
	assert((n == 0) || (n == 1));
	return n;
}


static rdma_cm_id_t *rbt_connect(const char *host, const char *port)
{
	assert(host != NULL);
	assert(port != NULL);

	struct rdma_addrinfo hints = { .ai_family = AF_INET, .ai_port_space = RDMA_PS_TCP }, *addr;
	//NOTE: missing const has already been fixed in librdmacm
	int err = rdma_getaddrinfo((char*)host, (char*)port, &hints, &addr);
	if (err != 0) {
		fprintf(stderr, "rdma_getaddrinfo(%s:%s): %s\n", host, port, gai_strerror(err));
		return NULL;
	}

	struct ibv_qp_init_attr attr = {
		.cap = { .max_send_wr = 1, .max_recv_wr = 1, .max_send_sge = 1, .max_recv_sge = 1 },
		.sq_sig_all = 1
	};

	rdma_cm_id_t *id = NULL, *result = NULL;
	if (rdma_create_ep(&id, addr, NULL, &attr) < 0) {
		fprintf(stderr, "rdma_create_ep(%s:%s): %s\n", host, port, strerror(errno));
		goto end;
	}
	if (rdma_connect(id, NULL) < 0) {
		fprintf(stderr, "rdma_connect(%s:%s): %s\n", host, port, strerror(errno));
		goto end;
	}
	result = id;

end:
	rdma_freeaddrinfo(addr);
	if ((result == NULL) && (id != NULL)) rdma_destroy_ep(id);
	return result;
}

void rbt_disconnect(rdma_cm_id_t *id)
{
	assert(id != NULL);
	if (rdma_disconnect(id) < 0) perror("rdma_disconnect");
	rdma_destroy_ep(id);
}


typedef struct rbt_cli_buf {
	int fd;
	void *addr;
	ibv_mr_t *read_mr;
	ibv_mr_t *write_mr;
} rbt_cli_buf_t;

#define rbt_cli_buf_initializer() (rbt_cli_buf_t){ .fd = -1 }

static void rbt_cli_buf_destroy(rbt_cli_buf_t *buf)
{
	assert(buf != NULL);

	if (buf->read_mr != NULL) rdma_dereg_mr(buf->read_mr);
	if (buf->write_mr != NULL) rdma_dereg_mr(buf->write_mr);
	if (buf->addr != NULL) munmap(buf->addr, buf_size * buf_nr);
	if (buf->fd >= 0) close(buf->fd);
	*buf = rbt_cli_buf_initializer();
}

typedef struct devpath devpath_t;

static bool rbt_cli_buf_init(rbt_cli_buf_t *buf, devpath_t *dpp, int cpu, rdma_cm_id_t *id)
{
	assert(buf != NULL);
	assert(dpp != NULL);
	assert(cpu >= 0);
	assert(id != NULL);

	char ifn[MAXPATHLEN + 64];
	snprintf(ifn, sizeof(ifn), "%s/block/%s/trace%d", debugfs_path, dpp->buts_name, cpu);

	// Need to open relay file with write permissions to enable RDMA write of consumed sub-buffer count
	if ((buf->fd = my_open(ifn, O_RDWR | O_NONBLOCK)) < 0) {
		fprintf(stderr, "open(%s): %s\n", ifn, strerror(errno));
		return false;
	}

	size_t length = buf_size * buf_nr;
	buf->addr = my_mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, buf->fd, 0);
	if (buf->addr == MAP_FAILED) {
		fprintf(stderr, "mmap(%s): %s\n", ifn, strerror(errno));
		buf->addr = NULL;
		goto error;
	}

	rblktrace_buf_header_t *header = buf->addr;
	if (header->magic != RBLKTRACE_HEADER_MAGIC) {
		fprintf(stderr, "Invalid relay buffer header magic: %zu\n", header->magic);
		goto error;
	}

	int access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ;
	if ((buf->read_mr = ibv_reg_mr(id->pd, buf->addr, length, access)) == NULL) {
		fprintf(stderr, "ibv_reg_mr(%s, %d): %s\n", ifn, access, strerror(errno));
		goto error;
	}
	access |= IBV_ACCESS_REMOTE_WRITE;
	if ((buf->write_mr = ibv_reg_mr(id->pd, buf->addr, sizeof(size_t), access)) == NULL) {
		fprintf(stderr, "ibv_reg_mr(%s, %d): %s\n", ifn, access, strerror(errno));
		goto error;
	}
	return true;

error:
	rbt_cli_buf_destroy(buf);
	return false;
}


static void rbt_cli_dev_destroy(devpath_t *dpp, int last_cpu)
{
	assert(dpp != NULL);

	if (dpp->rdma_bufs != NULL) {
		for (int cpu = 0; cpu < last_cpu; cpu++) {
			rbt_cli_buf_destroy(&(dpp->rdma_bufs[cpu]));
		}
		free(dpp->rdma_bufs);
		dpp->rdma_bufs = NULL;
	}
}

static bool rbt_cli_dev_init(devpath_t *dpp, rdma_cm_id_t *id)
{
	assert(dpp != NULL);

	if ((dpp->rdma_bufs = my_malloc(max_cpus * sizeof(rbt_cli_buf_t))) == NULL) return false;

	for (int cpu = 0; cpu < max_cpus; cpu++) {
		rbt_cli_buf_t *buf = &(dpp->rdma_bufs[cpu]);
		*buf = rbt_cli_buf_initializer();
		if (!CPU_ISSET_S(cpu, CPU_ALLOC_SIZE(max_cpus), online_cpus)) continue;

		if (!rbt_cli_buf_init(buf, dpp, cpu, id)) {
			rbt_cli_dev_destroy(dpp, cpu);
			return false;
		}
	}
	return true;
}


typedef struct list_head list_head_t;

static void rbt_cli_destroy(devpath_t *last_dpp)
{
	list_head_t *p;
	__list_for_each(p, &devpaths) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		if (dpp == last_dpp) break;
		rbt_cli_dev_destroy(dpp, max_cpus);
	}
}

static bool rbt_cli_init(rdma_cm_id_t *id)
{
	list_head_t *p;
	__list_for_each(p, &devpaths) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		if (!rbt_cli_dev_init(dpp, id)) {
			rbt_cli_destroy(dpp);
			return false;
		}
	}
	return true;
}


// Synchronous request-response with fixed response length
static bool rbt_send_recv(rdma_cm_id_t *id, void *req, size_t req_size, ibv_mr_t *req_mr,
                          int req_flags, void *resp, size_t resp_size, ibv_mr_t *resp_mr)
{
	assert(id != NULL);
	assert(req != NULL);
	assert(resp != NULL);
	assert(resp_mr != NULL);

	if (!rbt_post_recv(id, NULL, resp, resp_size, resp_mr)) return false;
	if (!rbt_post_send(id, NULL, req, req_size, req_mr, req_flags)) return false;

	ibv_wc_t wc;
	if (!rbt_get_send_comp(id, &wc)) return false;
	if (!rbt_get_recv_comp(id, &wc)) return false;

	if (wc.byte_len != resp_size) {
		fprintf(stderr, "Invalid response length: %u != %zu\n", wc.byte_len, resp_size);
		return false;
	}
	return true;
}

static bool check_magic(uint32_t magic)
{
	if (magic != BLK_IO_TRACE_MAGIC) fprintf(stderr, "Invalid magic value: %u\n", magic);
	return magic == BLK_IO_TRACE_MAGIC;
}


static bool rbt_send_open(rdma_cm_id_t *id)
{
	assert(id != NULL);

	size_t req_size = rbt_open_req_size(ndevs, max_cpus), resp_size = sizeof(rbt_open_resp_t);
	ibv_mr_t *mr = rbt_msg_buf_create(id, req_size + resp_size);
	if (mr == NULL) return false;
	rbt_open_req_t *req = mr->addr;
	rbt_open_resp_t *resp = mr->addr + req_size;

	*req = (rbt_open_req_t){ BLK_IO_TRACE_MAGIC, ndevs, max_cpus, buf_size, buf_nr };
	size_t i = 0;
	list_head_t *p;
	__list_for_each(p, &devpaths) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		rbt_dev_info_t *dev = rbt_dev_info_at(req, i);

		strncpy(dev->buts_name, dpp->buts_name, sizeof(dev->buts_name));
		dev->buts_name[sizeof(dev->buts_name) - 1] = '\0';

		for (int cpu = 0; cpu < max_cpus; cpu++) {
			rbt_cli_buf_t *buf = &(dpp->rdma_bufs[cpu]);
			dev->bufs[cpu] = (rbt_buf_info_t){ buf->addr, buf->read_mr ? buf->read_mr->rkey : 0,
			                                   buf->write_mr ? buf->write_mr->rkey : 0 };
		}
		i++;
	}

	bool result = false;
	if (!rbt_send_recv(id, req, req_size, mr, 0, resp, sizeof(*resp), mr)) goto end;
	if (!check_magic(resp->magic)) goto end;
	if (!(result = resp->result)) fprintf(stderr, "Open request failed\n");

end:
	rbt_msg_buf_destroy(mr);
	return result;
}


static bool rbt_send_close(rdma_cm_id_t *id)
{
	assert(id != NULL);

	size_t req_size = rbt_close_req_size(ndevs), resp_size = rbt_close_resp_size(ndevs, max_cpus);
	ibv_mr_t *mr = rbt_msg_buf_create(id, req_size + resp_size);
	if (mr == NULL) return false;
	rbt_close_req_t *req = mr->addr;;
	rbt_close_resp_t *resp = mr->addr + req_size;

	req->magic = BLK_IO_TRACE_MAGIC;
	size_t i = 0;
	list_head_t *p;
	__list_for_each(p, &devpaths) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		req->drops[i++] = dpp->drops;
	}

	bool result = false;
	if (!rbt_send_recv(id, req, req_size, mr, 0, resp, resp_size, mr)) goto end;
	if (!check_magic(resp->magic)) goto end;

	i = 0;
	__list_for_each(p, &devpaths) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		for (int cpu = 0; cpu < max_cpus; cpu++) {
			dpp->stats[cpu].data_read = *rbt_data_read_at(resp, max_cpus, i, cpu);
		}
		i++;
	}
	result = true;

end:
	rbt_msg_buf_destroy(mr);
	return result;
}


static int net_client_rdma(void)
{
	printf("rblktrace: connecting to %s\n", hostname);
	rdma_cm_id_t *id = rbt_connect(hostname, rdma_port);
	if (id == NULL) return 1;

	int result = 1;
	if (setup_buts() != 0) goto end;
	if (!rbt_cli_init(id)) goto end;
	if (!rbt_send_open(id)) goto end;
	start_buts();
	printf("rblktrace: connected!\n");

	if (stop_watch != 0) alarm(stop_watch);
	//TODO: fix race condition with signal handler
	while (!done) pause();

	//NOTE: signal handler has already called stop_tracers()
	//stop_tracers();
	get_all_drops();
	if (!rbt_send_close(id)) goto end;
	show_stats(&devpaths);
	result = 0;

end:
	rbt_cli_destroy(NULL);
	rbt_disconnect(id);
	return result;
}


typedef struct timespec timespec_t;

static inline timespec_t get_time(void)
{
	timespec_t ts;
	int status = clock_gettime(CLOCK_MONOTONIC, &ts);
	assert(status == 0);
	(void)status;
	return ts;
}

static inline timespec_t time_diff(timespec_t t1, timespec_t t0)
{
	return (t1.tv_nsec >= t0.tv_nsec) ? (timespec_t){ t1.tv_sec - t0.tv_sec    , t1.tv_nsec - t0.tv_nsec              }
	                                  : (timespec_t){ t1.tv_sec - t0.tv_sec - 1, t1.tv_nsec - t0.tv_nsec + 1000000000 };
}

static inline double time_to_msec(timespec_t t)
{
	return t.tv_sec * 1000.0 + t.tv_nsec / 1000000.0;
}


typedef enum rbt_buf_state {
/* -<-*/no_data = 0,//<-------------
// |	  |  ^                     |
// |      v  |                     |
/* |  */posted_header_read,//      |
// |      |                        |
// |      v                        |
/* |  */new_data,//<-------------  |
// |      |                     |  |
// |      v                     |  |
/* |  */posted_data_read,//     |  |
// |      |                     |  |
// |      v                     |  |
/* |  */done_data_read,//       |  |
// |      |                     |  |
// |      v                     |  |
/* |  */posted_header_write,//=>=---
// |
// |
/* -->*/posted_last_header_read,
//        |
//        v
/* -<-*/last_data,//<-----------------
// |      |                          |
// |      v                          |
/* |  */posted_last_data_read,//     |
// |      |                          |
// |      v                          |
/* |  */done_last_data_read,//       |
// |      |                          |
// |      v                          |
/* |  */posted_last_header_write,//->-
// |      |
// |      v
/* -->*/done_last_header_write
} rbt_buf_state_t;


typedef struct mmap_info mmap_info_t;

typedef struct rbt_srv_buf {
	int fd;
	mmap_info_t mmap_info;
	ibv_mr_t *mmap_mr;

	void *remote_addr;
	uint32_t read_rkey;
	uint32_t write_rkey;

	rbt_buf_state_t state;
	timespec_t timestamp;// last time header was read (taken at RDMA read completion)
	size_t header_reads;
	size_t data_reads;

	ibv_mr_t *header_mr;
	rblktrace_buf_header_t header;// mirror of the relay buffer header on the client side
} rbt_srv_buf_t;

#define rbt_srv_buf_initializer() (rbt_srv_buf_t){ .fd = -1 }

static inline size_t rbt_srv_buf_size(size_t buf_nr)
{
	return sizeof(rbt_srv_buf_t) + buf_nr * sizeof(size_t);
}


typedef struct rbt_srv_dev {
	struct rbt_srv_cli_ctx *ctx;
	devpath_t dp;
	char data[];
} rbt_srv_dev_t;

static inline size_t rbt_srv_dev_size(size_t ncpus, size_t buf_nr)
{
	return sizeof(rbt_srv_dev_t) + ncpus * rbt_srv_buf_size(buf_nr);
}


typedef struct rbt_srv_cli_ctx {
	list_head_t list_entry;

	rdma_cm_id_t *id;//NOTE: not owned by this struct
	time_t connect_time;
	char *hostname;
	ibv_mr_t *req_mr;// for close request

	int ndevs;
	int ncpus;
	int buf_size;
	int buf_nr;
	list_head_t devpaths;

	bool closing;
} rbt_srv_cli_ctx_t;

static const char *rbt_client_hostname(struct devpath *dpp)
{
	assert(dpp != NULL);
	return container_of(dpp, rbt_srv_dev_t, dp)->ctx->hostname;
}


static inline rbt_srv_buf_t *rbt_srv_buf_at(rbt_srv_dev_t *dev, size_t idx)
{
	assert(dev != NULL);
	return (rbt_srv_buf_t*)(dev->data + idx * rbt_srv_buf_size(dev->ctx->buf_nr));
}

static size_t rbt_header_reads(struct devpath *dpp, int cpu)
{
	assert(dpp != NULL);
	return rbt_srv_buf_at(container_of(dpp, rbt_srv_dev_t, dp), cpu)->header_reads;
}

static size_t rbt_data_reads(struct devpath *dpp, int cpu)
{
	assert(dpp != NULL);
	return rbt_srv_buf_at(container_of(dpp, rbt_srv_dev_t, dp), cpu)->data_reads;
}


static void rbt_srv_buf_destroy(rbt_srv_buf_t *buf)
{
	assert(buf != NULL);

	if (buf->header_mr != NULL) rdma_dereg_mr(buf->header_mr);
	if (buf->mmap_mr != NULL) rdma_dereg_mr(buf->mmap_mr);
	if (buf->mmap_info.fs_buf != NULL) munmap(buf->mmap_info.fs_buf, buf->mmap_info.fs_buf_len);
	if (buf->fd >= 0) {
		if (ftruncate(buf->fd, buf->mmap_info.fs_size) < 0) perror("ftruncate");
		close(buf->fd);
	}
	*buf = rbt_srv_buf_initializer();
}

static bool rbt_srv_buf_init(rbt_srv_buf_t *buf, rbt_buf_info_t *info, rbt_srv_dev_t *dev, int cpu)
{
	assert(buf != NULL);
	assert(info != NULL);
	assert(dev != NULL);
	assert(cpu >= 0);
	*buf = rbt_srv_buf_initializer();

	char hostdir[MAXPATHLEN + 64];
	int len = snprintf(hostdir, sizeof(hostdir), "%s-", dev->ctx->hostname);
	len += strftime(hostdir + len, sizeof(hostdir) - len, "%F-%T/", gmtime(&(dev->ctx->connect_time)));
	char ofn[MAXPATHLEN + 64];
	if (fill_ofname(ofn, sizeof(ofn), hostdir, dev->dp.buts_name, cpu) != 0) goto error;

	if ((buf->fd = my_open3(ofn, O_RDWR | O_CREAT, 0644)) < 0) {
		fprintf(stderr, "Open output file %s failed: %d/%s\n", ofn, errno, strerror(errno));
		goto error;
	}
	buf->mmap_info = (mmap_info_t){ .buf_size = dev->ctx->buf_size, .buf_nr = dev->ctx->buf_nr, .pagesize = pagesize };

	buf->remote_addr = info->addr;
	buf->read_rkey   = info->read_rkey;
	buf->write_rkey  = info->write_rkey;

	buf->header_mr = rbt_reg_msgs(dev->ctx->id, &(buf->header), rblktrace_buf_header_size(dev->ctx->buf_nr));
	if (buf->header_mr == NULL) goto error;

	// Ignore non-existent buffers/CPUs
	buf->state = (buf->remote_addr != NULL) ? no_data : done_last_header_write;
	buf->timestamp = get_time();
	return true;

error:
	rbt_srv_buf_destroy(buf);
	return false;
}


static void rbt_srv_dev_destroy(rbt_srv_dev_t *dev, int last_cpu)
{
	assert(dev != NULL);

	if (dev->dp.buts_name != NULL) free(dev->dp.buts_name);
	if (dev->dp.stats != NULL) free(dev->dp.stats);

	for (int cpu = 0; cpu < last_cpu; cpu++) {
		rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);
		rbt_srv_buf_destroy(buf);
	}
	free(dev);
}

static rbt_srv_dev_t *rbt_srv_dev_create(rbt_dev_info_t *info, rbt_srv_cli_ctx_t *ctx)
{
	assert(info != NULL);
	assert(ctx != NULL);

	rbt_srv_dev_t *dev = my_malloc(rbt_srv_dev_size(ctx->ncpus, ctx->buf_nr));
	if (dev == NULL) return NULL;

	dev->ctx = ctx;
	dev->dp = (devpath_t){ .fd = -1, .ncpus = ctx->ncpus };
	if ((dev->dp.buts_name = my_strdup(info->buts_name)) == NULL) goto error;
	if ((dev->dp.stats = my_calloc(ctx->ncpus * sizeof(struct pdc_stats))) == NULL) goto error;

	for (int cpu = 0; cpu < ctx->ncpus; cpu++) {
		rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);
		if (!rbt_srv_buf_init(buf, &(info->bufs[cpu]), dev, cpu)) {
			rbt_srv_dev_destroy(dev, cpu);
			return NULL;
		}
	}
	return dev;

error:
	rbt_srv_dev_destroy(dev, 0);
	return NULL;
}


static void rbt_srv_cli_ctx_destroy(rbt_srv_cli_ctx_t *ctx)
{
	assert(ctx != NULL);

	if (ctx->hostname != NULL) free(ctx->hostname);
	if (ctx->req_mr != NULL) rbt_msg_buf_destroy(ctx->req_mr);

	list_head_t *p, *q;
	list_for_each_safe(p, q, &(ctx->devpaths)) {
		list_del(p);
		devpath_t *dpp = list_entry(p, devpath_t, head);
		rbt_srv_dev_t *dev = container_of(dpp, rbt_srv_dev_t, dp);
		rbt_srv_dev_destroy(dev, ctx->ncpus);
	}
	free(ctx);
}

static rbt_srv_cli_ctx_t *rbt_srv_cli_ctx_create(rdma_cm_id_t *id, rbt_open_req_t *req)
{
	assert(id != NULL);
	assert(req != NULL);

	rbt_srv_cli_ctx_t *ctx = my_malloc(sizeof(rbt_srv_cli_ctx_t));
	if (ctx == NULL) return NULL;

	*ctx = (rbt_srv_cli_ctx_t){ .id = id, .ndevs = req->ndevs, .ncpus = req->ncpus,
	                            .buf_size = req->buf_size, .buf_nr = req->buf_nr };
	time(&ctx->connect_time);
	INIT_LIST_HEAD(&(ctx->devpaths));

	struct sockaddr *addr = rdma_get_peer_addr(id);
	assert(addr != NULL);
	assert(addr->sa_family == AF_INET);
	if ((ctx->hostname = strdup(inet_ntoa(((struct sockaddr_in*)addr)->sin_addr))) == NULL) goto error;

	if ((ctx->req_mr = rbt_msg_buf_create(id, rbt_close_req_size(req->ndevs))) == NULL) goto error;

	for (int i = 0; i < req->ndevs; i++) {
		rbt_srv_dev_t *dev = rbt_srv_dev_create(rbt_dev_info_at(req, i), ctx);
		if (dev == NULL) goto error;
		list_add_tail(&(dev->dp.head), &(ctx->devpaths));
	}

	if (!rbt_make_async(id->recv_cq_channel->fd)) goto error;
	if (!rbt_req_notify(id->recv_cq)) goto error;
	if (!rbt_post_recv(id, NULL, ctx->req_mr->addr, rbt_close_req_size(req->ndevs), ctx->req_mr)) goto error;

	return ctx;

error:
	rbt_srv_cli_ctx_destroy(ctx);
	return NULL;
}


static rdma_cm_id_t *rbt_listen(const char *port, int backlog)
{
	assert(port != NULL);

	struct rdma_addrinfo hints = { .ai_flags = RAI_PASSIVE, .ai_family = AF_INET, .ai_port_space = RDMA_PS_TCP }, *addr;
	//NOTE: missing const fixed in newer version of librdmacm
	int err = rdma_getaddrinfo((char*)"0.0.0.0", (char*)port, &hints, &addr);
	if (err != 0) {
		fprintf(stderr, "rdma_getaddrinfo: %s\n", gai_strerror(err));
		return NULL;
	}

	struct ibv_qp_init_attr attr = {
		.cap = {
			.max_send_wr = max_ndevs * max_ncpus,// header read or data read or header write, per buffer
			.max_recv_wr = 1,// open or close request
			.max_send_sge = 1, .max_recv_sge = 1,
			.max_inline_data = max(sizeof(rbt_close_resp_t), sizeof(size_t)/*consumed sub-buffer count*/)
		},
		.sq_sig_all = 1
	};

	rdma_cm_id_t *id = NULL, *result = NULL;
	if (rdma_create_ep(&id, addr, NULL, &attr) < 0) {
		perror("rdma_create_ep");
		goto end;
	}
	if (rdma_listen(id, backlog) < 0) {
		perror("rdma_listen");
		goto end;
	}
	result = id;

end:
	rdma_freeaddrinfo(addr);
	if ((result == NULL) && (id != NULL)) rdma_destroy_ep(id);
	return result;
}


typedef struct pollfd pollfd_t;

typedef struct rbt_srv {
	rdma_cm_id_t *id;
	pollfd_t *pfds;
	nfds_t nfds;
	list_head_t clients;
} rbt_srv_t;

static void rbt_srv_destroy(rbt_srv_t *srv)
{
	assert(srv != NULL);

	if (srv->id != NULL) rdma_destroy_ep(srv->id);
	if (srv->pfds != NULL) free(srv->pfds);

	list_head_t *p, *q;
	list_for_each_safe(p, q, &(srv->clients)) {
		list_del(p);
		rbt_srv_cli_ctx_t *ctx = list_entry(p, rbt_srv_cli_ctx_t, list_entry);
		rdma_cm_id_t *id = ctx->id;
		rbt_srv_cli_ctx_destroy(ctx);
		if (id != NULL) rbt_disconnect(id);
	}
	free(srv);
}

static rbt_srv_t *rbt_srv_create(void)
{
	rbt_srv_t *srv = my_calloc(sizeof(rbt_srv_t));
	if (srv == NULL) return NULL;

	INIT_LIST_HEAD(&(srv->clients));
	if ((srv->id = rbt_listen(rdma_port, 1)) == NULL) goto error;
	if ((srv->pfds = my_malloc(sizeof(pollfd_t))) == NULL) goto error;

	srv->nfds = 1;
	srv->pfds[0] = (pollfd_t){ srv->id->channel->fd, POLLIN, 0 };
	return srv;

error:
	rbt_srv_destroy(srv);
	return NULL;
}


static bool rbt_send_open_resp(rdma_cm_id_t *id, bool status)
{
	assert(id != NULL);

	rbt_open_resp_t resp = { BLK_IO_TRACE_MAGIC, status };
	if (!rbt_post_send(id, NULL, &resp, sizeof(resp), NULL, IBV_SEND_INLINE)) return false;

	ibv_wc_t wc;
	return rbt_get_send_comp(id, &wc);
}

static bool rbt_handle_open_req(rbt_srv_t *srv, rdma_cm_id_t *id, rbt_open_req_t *req, ibv_wc_t *wc)
{
	assert(srv != NULL);
	assert(id != NULL);
	assert(req != NULL);
	assert(wc != NULL);

	bool sent_resp = false;
	rbt_srv_cli_ctx_t *ctx = NULL;
	if (wc->byte_len < sizeof(rbt_open_req_t)) {
		fprintf(stderr, "Invalid open request length: %u < %zu\n", wc->byte_len, sizeof(rbt_open_req_t));
		goto error;
	}
	if (!check_magic(req->magic)) goto error;

	size_t req_size = rbt_open_req_size(req->ndevs, req->ncpus);
	if (wc->byte_len != req_size) {
		fprintf(stderr, "Invalid open request length: %u != %zu\n", wc->byte_len, req_size);
		goto error;
	}

	if ((ctx = rbt_srv_cli_ctx_create(id, req)) == NULL) goto error;

	pollfd_t *pfds = my_realloc(srv->pfds, (srv->nfds + 2) * sizeof(pollfd_t));
	if (pfds == NULL) goto error;
	srv->pfds = pfds;
	pfds[srv->nfds++] = (pollfd_t){ id->send_cq_channel->fd, POLLIN, 0 };
	pfds[srv->nfds++] = (pollfd_t){ id->recv_cq_channel->fd, POLLIN, 0 };

	sent_resp = true;
	if (!rbt_send_open_resp(id, true)) goto error;

	if (!rbt_make_async(id->send_cq_channel->fd)) goto error;
	if (!rbt_req_notify(id->send_cq)) goto error;

	list_add_tail(&(ctx->list_entry), &(srv->clients));
	printf("rdma server: connection from %s\n", ctx->hostname);
	return true;

error:
	if (!sent_resp) {
		srv->nfds -= 2;
		rbt_send_open_resp(id, false);
	}
	if (ctx != NULL) rbt_srv_cli_ctx_destroy(ctx);
	return false;
}


static bool rbt_accept(rbt_srv_t *srv)
{
	assert(srv != NULL);

	rdma_cm_id_t *id;
	if (rdma_get_request(srv->id, &id) < 0) {
		perror("rdma_get_request");
		return false;
	}

	bool result = false, accepted = false;
	size_t req_size = rbt_open_req_size(max_ndevs, max_ncpus);
	ibv_mr_t *req_mr = rbt_msg_buf_create(id, req_size);
	if (req_mr == NULL) goto end;
	rbt_open_req_t *req = req_mr->addr;

	if (!rbt_post_recv(id, NULL, req, req_size, req_mr)) goto end;

	if (rdma_accept(id, NULL) < 0) {
		perror("rdma_accept");
		goto end;
	}
	accepted = true;

	ibv_wc_t wc;
	if (!rbt_get_recv_comp(id, &wc)) goto end;

	result = rbt_handle_open_req(srv, id, req, &wc);

end:
	if (req_mr != NULL) rbt_msg_buf_destroy(req_mr);
	if (!result) {
		accepted ? rdma_disconnect(id) : rdma_reject(id, NULL, 0);
		rdma_destroy_ep(id);
	}
	return result;
}


typedef enum rbt_op {
	rbt_op_header_read,
	rbt_op_data_read,
	rbt_op_header_write
} rbt_op_t;

typedef struct rbt_comp_ctx {
	rbt_srv_dev_t *dev;
	int cpu;
	rbt_op_t op;
} rbt_comp_ctx_t;

static rbt_comp_ctx_t *rbt_comp_ctx_create(rbt_srv_dev_t *dev, int cpu, rbt_op_t op)
{
	rbt_comp_ctx_t *ctx = my_malloc(sizeof(rbt_comp_ctx_t));
	if (ctx != NULL) *ctx = (rbt_comp_ctx_t){ dev, cpu, op };
	return ctx;
}


static bool rbt_post_header_read(rbt_srv_dev_t *dev, int cpu)
{
	rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);

	rbt_comp_ctx_t *comp = rbt_comp_ctx_create(dev, cpu, rbt_op_header_read);
	if (comp == NULL) return false;

	if (rdma_post_read(dev->ctx->id, comp, (void*)&(buf->header.magic),
	                   rblktrace_buf_header_size(dev->ctx->buf_nr) - sizeof(size_t),
	                   buf->header_mr, 0, (uint64_t)buf->remote_addr + sizeof(size_t), buf->read_rkey) < 0) {
		perror("rdma_post_read");
		free(comp);
		return false;
	}

	buf->state = !dev->ctx->closing ? posted_header_read : posted_last_header_read;
	return true;
}

static bool rbt_header_read_comp(rbt_srv_dev_t *dev, int cpu)
{
	rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);
	assert((buf->state == posted_header_read) || (buf->state == posted_last_header_read));
	buf->timestamp = get_time();

	if (buf->header.magic != RBLKTRACE_HEADER_MAGIC) {
		fprintf(stderr, "Invalid relay buffer header magic: %zu\n", buf->header.magic);
		return false;
	}
	if (buf->header.produced < buf->header.consumed) {
		fprintf(stderr, "Invalid sub-buffer counts: produced %zu < consumed %zu\n",
		        buf->header.produced, buf->header.consumed);
		return false;
	}

	bool has_data = false;
	if (buf->header.produced > buf->header.consumed) {
		size_t subbuf_idx = buf->header.consumed % dev->ctx->buf_nr;
		size_t padding = buf->header.padding[subbuf_idx];
		size_t subbuf_size = dev->ctx->buf_size;

		if (padding > subbuf_size) {
			fprintf(stderr, "Invalid sub-buffer %zu padding: %zu > %zu\n", subbuf_idx, padding, subbuf_size);
			return false;
		}
		has_data = (subbuf_idx != 0) || (padding < subbuf_size - rblktrace_buf_header_size(dev->ctx->buf_nr));
	}

	buf->state = (buf->state == posted_header_read) ? (has_data ? new_data : no_data)
	                                                : (has_data ? last_data : done_last_header_write);
	buf->header_reads++;
	return true;
}


static bool rbt_setup_mmap(rbt_srv_buf_t *buf, unsigned int maxlen, rbt_srv_cli_ctx_t *ctx)
{
	assert(buf != NULL);
	assert(ctx != NULL);

	mmap_info_t *mip = &(buf->mmap_info);
	if ((buf->mmap_mr != NULL) && (mip->fs_off + maxlen > mip->fs_buf_len)) {
		rdma_dereg_mr(buf->mmap_mr);
		buf->mmap_mr = NULL;
	}

	if (setup_mmap(buf->fd, maxlen, mip, NULL) != 0) return false;
	return (buf->mmap_mr = rbt_reg_msgs(ctx->id, mip->fs_buf, mip->fs_buf_len)) != NULL;
}

static bool rbt_post_data_read(rbt_srv_dev_t *dev, int cpu)
{
	rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);
	assert((buf->state == new_data) || (buf->state == last_data));

	size_t subbuf_idx = buf->header.consumed % dev->ctx->buf_nr;
	assert(buf->header.padding[subbuf_idx] <= (size_t)dev->ctx->buf_size);

	size_t offset = subbuf_idx * dev->ctx->buf_size;
	size_t length = dev->ctx->buf_size - buf->header.padding[subbuf_idx];
	if (subbuf_idx == 0) {
		offset += rblktrace_buf_header_size(dev->ctx->buf_nr);
		length -= rblktrace_buf_header_size(dev->ctx->buf_nr);
	}
	if (!rbt_setup_mmap(buf, length, dev->ctx)) return false;

	rbt_comp_ctx_t *comp = rbt_comp_ctx_create(dev, cpu, rbt_op_data_read);
	if (comp == NULL) return false;

	void *local_addr = buf->mmap_info.fs_buf + buf->mmap_info.fs_off;
	uint64_t remote_addr = (uint64_t)buf->remote_addr + offset;
	if (rdma_post_read(dev->ctx->id, comp, local_addr, length, buf->mmap_mr, 0, remote_addr, buf->read_rkey) < 0) {
		perror("rdma_post_read");
		free(comp);
		return false;
	}

	buf->state = (buf->state == new_data) ? posted_data_read : posted_last_data_read;
	return true;
}

static bool rbt_data_read_comp(rbt_srv_dev_t *dev, int cpu, ibv_wc_t *wc)
{
	assert(wc != NULL);

	rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);
	assert((buf->state == posted_data_read) || (buf->state == posted_last_data_read));

	buf->mmap_info.fs_off += wc->byte_len;
	buf->mmap_info.fs_size += wc->byte_len;
	dev->dp.stats[cpu].data_read += wc->byte_len;
	buf->header.consumed++;

	buf->state = (buf->state == posted_data_read) ? done_data_read : done_last_data_read;
	buf->data_reads++;
	return true;
}


static bool rbt_post_header_write(rbt_srv_dev_t *dev, int cpu)
{
	rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);
	assert((buf->state == done_data_read) || (buf->state == done_last_data_read));

	rbt_comp_ctx_t *comp = rbt_comp_ctx_create(dev, cpu, rbt_op_header_write);
	if (comp == NULL) return false;

	if (rdma_post_write(dev->ctx->id, comp, (void*)&(buf->header.consumed), sizeof(size_t), NULL,
	                    IBV_SEND_INLINE, (uint64_t)buf->remote_addr, buf->write_rkey) < 0) {
		perror("rdma_post_write");
		free(comp);
		return false;
	}

	buf->state = (buf->state == done_data_read) ? posted_header_write : posted_last_header_write;
	return true;
}

static bool rbt_header_write_comp(rbt_srv_dev_t *dev, int cpu)
{
	rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);
	assert((buf->state == posted_header_write) || (buf->state == posted_last_header_write));

	if (buf->header.produced > buf->header.consumed) {
		buf->state = (buf->state == posted_header_write) ? new_data : last_data;
	} else {
		buf->state = (buf->state == posted_header_write) ? no_data : done_last_header_write;
	}
	return true;
}


static bool rbt_handle_comp(ibv_wc_t *wc)
{
	assert(wc != NULL);

	rbt_comp_ctx_t *comp = (rbt_comp_ctx_t*)wc->wr_id;
	assert(comp != NULL);
	bool result = false;

	if (wc->status != IBV_WC_SUCCESS) {
		fprintf(stderr, "Send request failed with %d\n", wc->status);
		goto end;
	}

	switch (comp->op) {
		case rbt_op_header_read: result = rbt_header_read_comp(comp->dev, comp->cpu); break;
		case rbt_op_data_read: result = rbt_data_read_comp(comp->dev, comp->cpu, wc); break;
		case rbt_op_header_write: result = rbt_header_write_comp(comp->dev, comp->cpu); break;
		default: assert(false);
	}

end:
	free(comp);
	return result;
}

static bool rbt_handle_send_comps(rbt_srv_cli_ctx_t *ctx)
{
	assert(ctx != NULL);

	if (!rbt_get_send_cq_event(ctx->id)) return false;
	if (!rbt_req_notify(ctx->id->send_cq)) return false;

	for (;;) {
		ibv_wc_t wc;
		int n = rbt_poll_cq(ctx->id->send_cq, &wc);
		if (n < 0) return false;
		if (n == 0) break;
		if (!rbt_handle_comp(&wc)) return false;
	}
	return true;
}


static bool rbt_handle_close_req(rbt_srv_cli_ctx_t *ctx, ibv_wc_t *wc)
{
	assert(ctx != NULL);
	assert(wc != NULL);

	if (wc->byte_len < sizeof(rbt_close_req_t)) {
		fprintf(stderr, "Invalid close request length: %u < %zu\n", wc->byte_len, sizeof(rbt_close_req_t));
		return false;
	}

	rbt_close_req_t *req = ctx->req_mr->addr;
	if (!check_magic(req->magic)) return false;

	size_t req_size = rbt_close_req_size(ctx->ndevs);
	if (wc->byte_len != req_size) {
		fprintf(stderr, "Invalid close request length: %u != %zu\n", wc->byte_len, req_size);
		return false;
	}

	list_head_t *p;
	size_t i = 0;
	__list_for_each(p, &(ctx->devpaths)) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		dpp->drops = req->drops[i++];
	}

	ctx->closing = true;
	return true;
}

static bool rbt_send_close_resp(rbt_srv_cli_ctx_t *ctx)
{
	assert(ctx != NULL);

	size_t resp_size = rbt_close_resp_size(ctx->ndevs, ctx->ncpus);
	ibv_mr_t *resp_mr = rbt_msg_buf_create(ctx->id, resp_size);
	if (resp_mr == NULL) return false;
	rbt_close_resp_t *resp = resp_mr->addr;
	resp->magic = BLK_IO_TRACE_MAGIC;

	list_head_t *p;
	size_t i = 0;
	__list_for_each(p, &(ctx->devpaths)) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		for (int cpu = 0; cpu < ctx->ncpus; cpu++) {
			*rbt_data_read_at(resp, ctx->ncpus, i, cpu) = dpp->stats[cpu].data_read;
		}
		i++;
	}

	bool result = false;
	if (!rbt_post_send(ctx->id, NULL, resp, resp_size, resp_mr, 0)) goto end;

	ibv_wc_t wc;
	if (!rbt_get_send_comp(ctx->id, &wc)) goto end;
	result = true;

end:
	rbt_msg_buf_destroy(resp_mr);
	return result;
}


static bool rbt_handle_recv_comps(rbt_srv_cli_ctx_t *ctx)
{
	assert(ctx != NULL);

	if (!rbt_get_recv_cq_event(ctx->id)) return false;
	//NOTE: no need to request more completion events, this is the last recv request posted

	ibv_wc_t wc;
	int n = rbt_poll_cq(ctx->id->recv_cq, &wc);
	if (n == 0) fprintf(stderr, "No recv completions\n");
	if (n <= 0) return false;

	if (!rbt_make_sync(ctx->id->send_cq_channel->fd)) return false;
	if (!rbt_make_sync(ctx->id->recv_cq_channel->fd)) return false;
	return rbt_handle_close_req(ctx, &wc);
}


static bool rbt_handle_buffer(rbt_srv_dev_t *dev, int cpu)
{
	rbt_srv_buf_t *buf = rbt_srv_buf_at(dev, cpu);

	switch (buf->state) {
		case no_data:
			if (dev->ctx->closing || (time_to_msec(time_diff(get_time(), buf->timestamp)) >= (double)rdma_interval)) {
				return rbt_post_header_read(dev, cpu);
			}
			return true;

		case posted_header_read:       return true;
		case new_data:                 return rbt_post_data_read(dev, cpu);
		case posted_data_read:         return true;
		case done_data_read:           return rbt_post_header_write(dev, cpu);
		case posted_header_write:      return true;
		case posted_last_header_read:  return true;
		case last_data:                return rbt_post_data_read(dev, cpu);
		case posted_last_data_read:    return true;
		case done_last_data_read:      return rbt_post_header_write(dev, cpu);
		case posted_last_header_write: return true;
		case done_last_header_write:   return true;

		default: assert(false); return false;
	}
}


// Returns false on failure or if close response has been sent to the client
static bool rbt_handle_client(rbt_srv_cli_ctx_t *ctx)
{
	assert(ctx != NULL);

	int done = 0;
	list_head_t *p;
	__list_for_each(p, &(ctx->devpaths)) {
		devpath_t *dpp = list_entry(p, devpath_t, head);
		rbt_srv_dev_t *dev = container_of(dpp, rbt_srv_dev_t, dp);

		for (int cpu = 0; cpu < ctx->ncpus; cpu++) {
			if (!rbt_handle_buffer(dev, cpu)) return false;
			if (rbt_srv_buf_at(dev, cpu)->state == done_last_header_write) done++;
		}
	}

	if (done == ctx->ndevs * ctx->ncpus) {
		show_stats(&(ctx->devpaths));
		rbt_send_close_resp(ctx);
		return false;
	}
	return true;
}

static void rbt_remove_client(rbt_srv_t *srv, rbt_srv_cli_ctx_t *ctx, size_t pfd_idx)
{
	assert(srv != NULL);
	assert(ctx != NULL);
	assert(pfd_idx < srv->nfds);
	assert(pfd_idx % 2 == 1);

	list_del(&(ctx->list_entry));
	rdma_cm_id_t *id = ctx->id;
	rbt_srv_cli_ctx_destroy(ctx);
	if (id != NULL) rbt_disconnect(id);
	if (pfd_idx < srv->nfds - 2) memmove(&(srv->pfds[pfd_idx]), &(srv->pfds[pfd_idx + 2]), srv->nfds - pfd_idx - 2);
	srv->nfds -= 2;
}


static int net_server_rdma(void)
{
	rbt_srv_t *srv = rbt_srv_create();
	if (srv == NULL) return 1;
	printf("rdma server: waiting for connections...\n");

	int result = 0;
	while (!done) {
		//TODO: fix race condition with signal handler
		int events = poll(srv->pfds, srv->nfds, (srv->nfds > 1) ? rdma_interval : -1);
		if ((events < 0) && (errno != EINTR)) {
			perror("poll");
			result = 1;
			break;
		}

		if ((events > 0) && (srv->pfds[0].revents & POLLIN)) rbt_accept(srv);

		list_head_t *p, *q;
		size_t i = 1;
		list_for_each_safe(p, q, &(srv->clients)) {
			rbt_srv_cli_ctx_t *ctx = list_entry(p, rbt_srv_cli_ctx_t, list_entry);

			if ((events > 0) && (srv->pfds[i].revents & POLLIN)) {
				events--;
				if (!rbt_handle_send_comps(ctx)) {
					rbt_remove_client(srv, ctx, i);
					continue;
				}
			}

			if ((events > 0) && (srv->pfds[i + 1].revents & POLLIN)) {
				events--;
				if (!rbt_handle_recv_comps(ctx)) {
					rbt_remove_client(srv, ctx, i);
					continue;
				}
				srv->pfds[i + 1] = (pollfd_t){ -1, 0, 0 };
			}

			if (!rbt_handle_client(ctx)) {
				rbt_remove_client(srv, ctx, i);
				continue;
			}
			i += 2;
		}
	}

	rbt_srv_destroy(srv);
	return result;
}


#endif// RBLKTRACE
