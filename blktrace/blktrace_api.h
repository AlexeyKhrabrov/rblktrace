#ifndef BLKTRACEAPI_H
#define BLKTRACEAPI_H

#include <asm/types.h>

/*
 * Trace categories
 */
enum {
	BLK_TC_READ	= 1 << 0,	/* reads */
	BLK_TC_WRITE	= 1 << 1,	/* writes */
	BLK_TC_FLUSH	= 1 << 2,	/* flush */
	BLK_TC_SYNC	= 1 << 3,	/* sync */
	BLK_TC_QUEUE	= 1 << 4,	/* queueing/merging */
	BLK_TC_REQUEUE	= 1 << 5,	/* requeueing */
	BLK_TC_ISSUE	= 1 << 6,	/* issue */
	BLK_TC_COMPLETE	= 1 << 7,	/* completions */
	BLK_TC_FS	= 1 << 8,	/* fs requests */
	BLK_TC_PC	= 1 << 9,	/* pc requests */
	BLK_TC_NOTIFY	= 1 << 10,	/* special message */
	BLK_TC_AHEAD	= 1 << 11,	/* readahead */
	BLK_TC_META	= 1 << 12,	/* metadata */
	BLK_TC_DISCARD	= 1 << 13,	/* discard requests */
	BLK_TC_DRV_DATA	= 1 << 14,	/* binary driver data */
	BLK_TC_FUA	= 1 << 15,	/* fua requests */

	BLK_TC_END	= 1 << 15,	/* we've run out of bits! */
};

#define BLK_TC_SHIFT		(16)
#define BLK_TC_ACT(act)		((act) << BLK_TC_SHIFT)

/*
 * Basic trace actions
 */
enum {
	__BLK_TA_QUEUE = 1,		/* queued */
	__BLK_TA_BACKMERGE,		/* back merged to existing rq */
	__BLK_TA_FRONTMERGE,		/* front merge to existing rq */
	__BLK_TA_GETRQ,			/* allocated new request */
	__BLK_TA_SLEEPRQ,		/* sleeping on rq allocation */
	__BLK_TA_REQUEUE,		/* request requeued */
	__BLK_TA_ISSUE,			/* sent to driver */
	__BLK_TA_COMPLETE,		/* completed by driver */
	__BLK_TA_PLUG,			/* queue was plugged */
	__BLK_TA_UNPLUG_IO,		/* queue was unplugged by io */
	__BLK_TA_UNPLUG_TIMER,		/* queue was unplugged by timer */
	__BLK_TA_INSERT,		/* insert request */
	__BLK_TA_SPLIT,			/* bio was split */
	__BLK_TA_BOUNCE,		/* bio was bounced */
	__BLK_TA_REMAP,			/* bio was remapped */
	__BLK_TA_ABORT,			/* request aborted */
	__BLK_TA_DRV_DATA,		/* binary driver data */
};

/*
 * Notify events.
 */
enum blktrace_notify {
	__BLK_TN_PROCESS = 0,		/* establish pid/name mapping */
	__BLK_TN_TIMESTAMP,		/* include system clock */
	__BLK_TN_MESSAGE,               /* Character string message */
};

/*
 * Trace actions in full. Additionally, read or write is masked
 */
#define BLK_TA_QUEUE		(__BLK_TA_QUEUE | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_BACKMERGE	(__BLK_TA_BACKMERGE | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_FRONTMERGE	(__BLK_TA_FRONTMERGE | BLK_TC_ACT(BLK_TC_QUEUE))
#define	BLK_TA_GETRQ		(__BLK_TA_GETRQ | BLK_TC_ACT(BLK_TC_QUEUE))
#define	BLK_TA_SLEEPRQ		(__BLK_TA_SLEEPRQ | BLK_TC_ACT(BLK_TC_QUEUE))
#define	BLK_TA_REQUEUE		(__BLK_TA_REQUEUE | BLK_TC_ACT(BLK_TC_REQUEUE))
#define BLK_TA_ISSUE		(__BLK_TA_ISSUE | BLK_TC_ACT(BLK_TC_ISSUE))
#define BLK_TA_COMPLETE		(__BLK_TA_COMPLETE| BLK_TC_ACT(BLK_TC_COMPLETE))
#define BLK_TA_PLUG		(__BLK_TA_PLUG | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_UNPLUG_IO	(__BLK_TA_UNPLUG_IO | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_UNPLUG_TIMER	(__BLK_TA_UNPLUG_TIMER | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_INSERT		(__BLK_TA_INSERT | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_SPLIT		(__BLK_TA_SPLIT)
#define BLK_TA_BOUNCE		(__BLK_TA_BOUNCE)
#define BLK_TA_REMAP		(__BLK_TA_REMAP | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_ABORT		(__BLK_TA_ABORT | BLK_TC_ACT(BLK_TC_QUEUE))
#define BLK_TA_DRV_DATA		(__BLK_TA_DRV_DATA | BLK_TC_ACT(BLK_TC_DRV_DATA))

#define BLK_TN_PROCESS		(__BLK_TN_PROCESS | BLK_TC_ACT(BLK_TC_NOTIFY))
#define BLK_TN_TIMESTAMP	(__BLK_TN_TIMESTAMP | BLK_TC_ACT(BLK_TC_NOTIFY))
#define BLK_TN_MESSAGE		(__BLK_TN_MESSAGE | BLK_TC_ACT(BLK_TC_NOTIFY))

#define BLK_IO_TRACE_MAGIC	0x65617400
#define BLK_IO_TRACE_VERSION	0x07

/*
 * The trace itself
 */
struct blk_io_trace {
	__u32 magic;		/* MAGIC << 8 | version */
	__u32 sequence;		/* event number */
	__u64 time;		/* in nanoseconds */
	__u64 sector;		/* disk offset */
	__u32 bytes;		/* transfer length */
	__u32 action;		/* what happened */
	__u32 pid;		/* who did it */
	__u32 device;		/* device identifier (dev_t) */
	__u32 cpu;		/* on what cpu did it happen */
	__u16 error;		/* completion error */
	__u16 pdu_len;		/* length of data after this trace */
};

/*
 * The remap event
 */
struct blk_io_trace_remap {
	__u32 device_from;
	__u32 device_to;
	__u64 sector_from;
};

/*
 * User setup structure passed with BLKSTARTTRACE
 */
struct blk_user_trace_setup {
	char name[32];			/* output */
	__u16 act_mask;			/* input */
	__u32 buf_size;			/* input */
	__u32 buf_nr;			/* input */
	__u64 start_lba;
	__u64 end_lba;
	__u32 pid;
#ifdef CONFIG_RBLKTRACE
	int use_rdma;// input
#endif
};


#ifdef CONFIG_RBLKTRACE

#define RBLKTRACE_HEADER_MAGIC 0x0123456789ABCDEFL

// Per-cpu relay buffer header; located at the start of the first sub-buffer
typedef struct rblktrace_buf_header {
	//NOTE: the fields are volatile since they are RDMA-read/written
	volatile size_t consumed;
	volatile size_t magic;
	volatile size_t produced;
	volatile size_t padding[];// entry per sub-buffer
} rblktrace_buf_header_t;

static inline size_t rblktrace_buf_header_size(size_t n_subbufs)
{
	return sizeof(rblktrace_buf_header_t) + n_subbufs * sizeof(size_t);
}

#endif// CONFIG_RBLKTRACE


#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)

#endif
