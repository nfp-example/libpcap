/**
 * pcap-nfpshm.c: Packet capture interface for NFP SHM pcap firmware
 *
 */

/** Make capturetest
return processed;
root@cbtest3:~# tcpreplay -i p2p1 -l 300 -K -q -p 10000 pablo/pcaps/csum.pcap

./configure  -with-nfpshm=/root/gavin/nfp-common/host
make
cc -fpic -I.  -I/root/gavin/nfp-common/host/src -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include   -DHAVE_CONFIG_H  -D_U_="__attribute__((unused))" -g -O2    -I. -L. -o capturetest ./tests/capturetest.c libpcap.a -ldbus-1 ../nfp-common/host/build/nfp_ipc.o ../nfp-common/host/build/nfp_support.o -L/opt/netronome/lib -L/usr/lib/x86_64-linux-gnu/ -lnfp -lnfp_nffw -lhugetlbfs -ljansson
*/
/** Includes
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>			/* optionally get BSD define */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "pcap-int.h"

#include <ctype.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct mbuf;		/* Squelch compiler warnings on some platforms for */
struct rtentry;		/* declarations in <net/if.h> */
#include <net/if.h>

#include "nfp_ipc.h"
#include "nfp_support.h"
#include "pktgencap.h"
#include "firmware/pcap.h"
#include "pcap-nfpshm.h"

/** struct pcap_nfmshm - private data for NFP SHM capture firmware
 */
struct pcap_nfpshm {
    pcap_t *pcap;
    struct pcap_nfpshm *next_nfpshm;

	struct pcap_stat stat;
    int nonblock;

    struct nfp *nfp;
    struct {
        char *base;
        size_t size;
    } shm;
    struct nfp_ipc *nfp_ipc;
    int nfp_ipc_client;
    struct pktgen_ipc_msg *pktgen_msg;
    struct nfp_ipc_msg *msg;

    int ifup;
    int msg_sent;
    int next_seq;
    int current_buffer;
    int next_pkt;
    int next_buffer;
    int buffers_to_recycle[2];
};

/** Static variables
 */
static struct pcap_nfpshm *nfpshms = NULL;
static int atexit_handler_installed = 0;
static const char *shm_filename="/tmp/nfp_shm.lock";
static int shm_key = 'x';


/** To be removed
 */
struct dag_record_t
{
    int ts;
    int wlen;
    int rlen;
    int lctr;
    int type;
};
static const unsigned short endian_test_word = 0x0100;
#define IS_BIGENDIAN() (*((unsigned char *)&endian_test_word))
#define MAX_DAG_PACKET 65536
static unsigned char TempPkt[MAX_DAG_PACKET];

/** Forward function declarations
 */
static void nfpshm_atexit_handler(void);

/** nfpshm_alloc_shm - from pktgen_alloc_shm
 */
static int
nfpshm_alloc_shm(struct pcap_nfpshm *pd)
{
    pd->nfp = nfp_init(-1);
    pd->shm.size = nfp_shm_alloc(pd->nfp,
                                shm_filename, shm_key,
                                pd->shm.size, 0);
    if (pd->shm.size == 0) {
        fprintf(stderr,"Failed to find NFP SHM\n");
        return -1;
    }

    pd->shm.base = nfp_shm_data(pd->nfp);
    pd->nfp_ipc = (struct nfp_ipc *)pd->shm.base;
    fprintf(stderr,"%s %p %ld\n",__func__,pd->shm.base,pd->shm.size);
    return 0;
}

/** nfpshm_add - add an NFP SHM pcap (already created) to static list for deletion at exit
 */
static void
nfpshm_add(struct pcap_nfpshm *pd)
{
    fprintf(stderr,"%s\n",__func__);
	if (!atexit_handler_installed) {
		atexit(nfpshm_atexit_handler);
		atexit_handler_installed = 1;
	}

    pd->next_nfpshm = nfpshms;
    nfpshms = pd;
    fprintf(stderr,"handler installed %d shms %p\n",atexit_handler_installed,nfpshms);
}

/** nfpshm_delete - Remove an NFP SHM pcap from list for deletion at exit
 */
static void
nfpshm_delete(struct pcap_nfpshm *pd)
{
    fprintf(stderr,"%s\n",__func__);
    struct pcap_nfpshm *ptr, **prev;
    prev = &nfpshms;
    for (ptr = nfpshms; ptr && (ptr!=pd); ptr=ptr->next_nfpshm) {
        prev = &ptr->next_nfpshm;
    }
    if (ptr==pd) {
        *prev = ptr->next_nfpshm;
    }
}

/** nfpshm_cleanup - Stop an NFP SHM pcap instances cleanly and remove from exit cleanup list
 */
static void
nfpshm_cleanup(pcap_t *p)
{
	struct pcap_nfpshm *pd;

    fprintf(stderr,"%s\n",__func__);
	if (p != NULL) {
		pd = p->priv;

        nfp_ipc_stop_client(pd->nfp_ipc, pd->nfp_ipc_client);

		nfpshm_delete(pd);

		pcap_cleanup_live_common(p);
	}
	/* Note: don't need to call close(p->fd) here as dag_close(p->fd) does this. */
}

/** nfpshm_atexit_handler - clean up all NFP SHM pcap instances for exit
 */
static void
nfpshm_atexit_handler(void)
{
    fprintf(stderr,"%s\n",__func__);
	while (nfpshms) {
        nfpshm_cleanup(nfpshms->pcap);
	}
}

/** nfpshm_setfilter - Set BPF filter in PCAP software - no BPF at present in pcap firmware
 */
static int
nfpshm_setfilter(pcap_t *p, struct bpf_program *fp)
{
	if (!p)
		return -1;
	if (!fp) {
		strncpy(p->errbuf, "setfilter: No filter specified",
			sizeof(p->errbuf));
		return -1;
	}

	/* Make our private copy of the filter */

	if (install_bpf_program(p, fp) < 0)
		return -1;

	return (0);
}

/** nfpshm_setnonblock - Set PCAP to be nonblocking (on/off)
 */
static int
nfpshm_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
	struct pcap_nfpshm *pd = p->priv;
    pd->nonblock = nonblock;
	return (0);
}

/** nfpshm_getnonblock - Get state of PCAP nonblocking
*/
static int
nfpshm_getnonblock(pcap_t *p, char *errbuf)
{
	struct pcap_nfpshm *pd = p->priv;
    return pd->nonblock;
}

/** nfpshm_set_datalink - Set data link of pcap to one of those supported
*/
static int
nfpshm_set_datalink(pcap_t *p, int dlt)
{
	p->linktype = dlt;

	return (0);
}

/** nfpshm_get_datalink - Get data link types
*/
static int
nfpshm_get_datalink(pcap_t *p)
{
	struct pcap_nfpshm *pd = p->priv;
	int index=0, dlt_index=0;

	if (p->dlt_list == NULL && (p->dlt_list = malloc(255*sizeof(*(p->dlt_list)))) == NULL) {
		(void)snprintf(p->errbuf, sizeof(p->errbuf), "malloc: %s", pcap_strerror(errno));
		return (-1);
	}

	p->linktype = 0;

    if (p->dlt_list != NULL) {
        p->dlt_list[dlt_index++] = DLT_EN10MB;
        p->dlt_list[dlt_index++] = DLT_DOCSIS;
    }
    if(!p->linktype)
        p->linktype = DLT_EN10MB;

	p->dlt_list[dlt_index++] = DLT_ERF;

	p->dlt_count = dlt_index;

	if(!p->linktype)
		p->linktype = DLT_ERF;

	return p->linktype;
}

/* nfpshm_read_send_msg - Send an NFP IPC message if required
 */
static void
nfpshm_read_send_msg(struct pcap_nfpshm *pd)
{
    if (pd->msg_sent)
        return;
    if (pd->current_buffer<0) {
        //fprintf(stderr, "sending message\n");
        pd->pktgen_msg->reason = PKTGEN_IPC_RETURN_BUFFERS;
        pd->pktgen_msg->ack = 0;
        pd->pktgen_msg->return_buffers.buffers[0] = pd->buffers_to_recycle[0];
        pd->pktgen_msg->return_buffers.buffers[1] = pd->buffers_to_recycle[1];
        pd->buffers_to_recycle[0] = -1;
        pd->buffers_to_recycle[1] = -1;
        pd->pktgen_msg->return_buffers.buffers_to_claim = 2;
        nfp_ipc_client_send_msg(pd->nfp_ipc, pd->nfp_ipc_client, pd->msg);
        pd->msg_sent = 1;
    } else if (pd->next_buffer<0) {
        pd->pktgen_msg->reason = PKTGEN_IPC_RETURN_BUFFERS;
        pd->pktgen_msg->ack = 0;
        pd->pktgen_msg->return_buffers.buffers[0] = pd->buffers_to_recycle[0];
        pd->pktgen_msg->return_buffers.buffers[1] = pd->buffers_to_recycle[1];
        pd->buffers_to_recycle[0] = -1;
        pd->buffers_to_recycle[1] = -1;
        pd->pktgen_msg->return_buffers.buffers_to_claim = 1;
        nfp_ipc_client_send_msg(pd->nfp_ipc, pd->nfp_ipc_client, pd->msg);
        pd->msg_sent = 1;
    }
}

/* nfpshm_read_poll_msg - Poll for message reply from nfp ipc
 */
static void
nfpshm_read_poll_msg(struct pcap_nfpshm *pd)
{
    int poll;
    struct nfp_ipc_event event;
    static int claims=0;
    struct pktgen_ipc_msg *msg;
    
    if (!pd->msg_sent)
        return;
       
    poll = nfp_ipc_client_poll(pd->nfp_ipc, pd->nfp_ipc_client, 0 /*timeout*/, &event);
    if (poll==NFP_IPC_EVENT_SHUTDOWN) {
        pd->ifup = 0;
        return;
    }
    if (poll==NFP_IPC_EVENT_MESSAGE) {
        pd->msg_sent = 0;

        msg = (struct pktgen_ipc_msg *)&event.msg->data[0];
        if (msg->reason == PKTGEN_IPC_RETURN_BUFFERS) {
            int claimed_buffer;
            claimed_buffer = msg->return_buffers.buffers[0];
            claims++;
            //fprintf(stderr, "%d: got claimed_buffer %d (currently at %d.%d)\n", claims, claimed_buffer, pd->current_buffer, pd->next_pkt);
            if (claimed_buffer>=0) {
                if (pd->current_buffer<0) {
                    pd->current_buffer = claimed_buffer;
                } else {
                    pd->next_buffer = claimed_buffer;
                }
            }
            if (msg->return_buffers.buffers[1]>=0) {
                pd->next_buffer = msg->return_buffers.buffers[1];
            }
        }
    }
}

/* nfpshm_read - Read packets and invoke callback handler
 *  Returns the number of packets handled, -1 if an
 *  error occured, or -2 if we were told to break out of the loop.
 */
static int total_packets=0;
static int
nfpshm_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_nfpshm *pd = p->priv;
	unsigned int processed = 0;
    uint64_t phys_offset;
    struct pcap_buffer *pcap_buffer;
    int j;

    struct pcap_pkthdr	pcap_header;

    if (!pd->ifup)
        return -1;

    if (p->break_loop) {
        p->break_loop = 0;
        return -2;
    }

    nfpshm_read_send_msg(pd);
    nfpshm_read_poll_msg(pd);

    if (!pd->ifup)
        return -1;

    if (pd->current_buffer<0)
        return 0;

    if (cnt<0) cnt=4000;
#define PCIE_HUGEPAGE_SIZE (1<<20)
    phys_offset = PCIE_HUGEPAGE_SIZE + (pd->current_buffer<<18);
    pcap_buffer = (struct pcap_buffer *)(pd->shm.base + phys_offset);

    while (!p->break_loop) {
        j = pd->next_pkt;

        if ((pcap_buffer->hdr.total_packets!=0) && (j == pcap_buffer->hdr.total_packets)) {
            if (pd->buffers_to_recycle[0]<0) {
                pd->buffers_to_recycle[0] = pd->current_buffer;
            } else {
                pd->buffers_to_recycle[1] = pd->current_buffer;
            }
            pd->next_pkt = 0;
            pd->current_buffer = pd->next_buffer;
            pd->next_buffer = -1;
            if (pd->current_buffer<0) {
                return processed;
            }
            j = pd->next_pkt;
            phys_offset = PCIE_HUGEPAGE_SIZE + (pd->current_buffer<<18);
            pcap_buffer = (struct pcap_buffer *)(pd->shm.base + phys_offset);
        }

        if (pcap_buffer->pkt_desc[j].offset==0) {
            //usleep(1000);
            //fprintf(stderr, "Poll %d.%d\n", pd->current_buffer, j);
            nfpshm_read_send_msg(pd);
            nfpshm_read_poll_msg(pd);
            if (!pd->ifup)
                return -1;
        }
        if (pcap_buffer->pkt_desc[j].offset==0) {
            break;
        }
        pd->next_pkt++;
        if (0) {
            fprintf(stderr, "%d: %d.%d: %04x %04x %08x\n",
                    j,
                    pcap_buffer->hdr.total_packets,
                    pcap_buffer->dmas_completed,
                    pcap_buffer->pkt_desc[j].offset,
                    pcap_buffer->pkt_desc[j].num_blocks,
                    pcap_buffer->pkt_desc[j].seq
                );
        }
        //mem_dump(((char *)pcap_buffer) + (pcap_buffer->pkt_desc[j].offset<<6), 64);
        // skipping bpf
        /* convert between timestamp formats */
        pcap_header.ts.tv_sec = 0;
        pcap_header.ts.tv_usec = pcap_buffer->pkt_desc[j].seq;
        //register unsigned long long ts;
        //ts = header->ts;
        //if (IS_BIGENDIAN()) ts=SWAPLL(ts);

        /* Fill in our own header data */
        pcap_header.caplen = pcap_buffer->pkt_desc[j].num_blocks*64;
        pcap_header.len = pcap_header.caplen;
        pd->stat.ps_recv++;
        callback(user, &pcap_header, ((char *)pcap_buffer) + (pcap_buffer->pkt_desc[j].offset<<6));
        processed++;
        total_packets++;
        if ((total_packets%(1000*1000))==0) {
            fprintf(stderr,"Total packets handled %d0Mpps\n",total_packets/(1000*1000));
        }
        if (processed==cnt)
            break;
    }
    if (p->break_loop) {
        p->break_loop = 0;
        return -2;
    }
    //if (processed>0) fprintf(stderr, "Returning from read at %d.%d\n", pd->current_buffer, pd->next_pkt);
    return processed;

#if 0
	unsigned int nonblocking = pd->nonblock;
	unsigned int num_ext_hdr = 0;
	unsigned int ticks_per_second;

	/* Get the next bufferful of packets (if necessary). */
	while (pd->dag_mem_top - pd->dag_mem_bottom < dag_record_size) {

		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (p->break_loop) {
			/*
			 * Yes - clear the flag that indicates that
			 * it has, and return -2 to indicate that
			 * we were told to break out of the loop.
			 */
			p->break_loop = 0;
			return -2;
		}

        //GJS
        // check for response from nfp_ipc with new host buffer to monitor
        if (1) {
            poll = nfp_ipc_client_poll(pd->nfp_ipc, pd->nfp_ipc_client, timeout, &event);
            if (poll==NFP_IPC_EVENT_SHUTDOWN) {
                i = argc;
                break;
            }
            if (poll==NFP_IPC_EVENT_MESSAGE) {
            }
        }
        // send message if response not pending AND we have no host buffer to monitor
        // put in any host buffers to recycle
        if (1) {
            pktgen_msg->reason = PKTGEN_IPC_RETURN_HOST_BUFFER;
            pktgen_msg->ack = 0;
            pktgen_msg->return_buffer.buffer = 0;
            nfp_ipc_client_send_msg(pd->nfp_ipc, pd->nfp_ipc_client, msg);
        }

		/* dag_offset does not support timeouts */
		pd->dag_mem_top = dag_offset(p->fd, &(pd->dag_mem_bottom), flags);

		if (nonblocking && (pd->dag_mem_top - pd->dag_mem_bottom < dag_record_size))
		{
			/* Pcap is configured to process only available packets, and there aren't any, return immediately. */
			return 0;
		}

		if(!nonblocking &&
		   pd->dag_timeout &&
		   (pd->dag_mem_top - pd->dag_mem_bottom < dag_record_size))
		{
			/* Blocking mode, but timeout set and no data has arrived, return anyway.*/
			return 0;
		}

	}

	/* Process the packets. */
	while (pd->dag_mem_top - pd->dag_mem_bottom >= dag_record_size) {

		unsigned short packet_len = 0;
		int caplen = 0;
		struct pcap_pkthdr	pcap_header;

		struct dag_record_t *header = (struct dag_record_t *)(pd->dag_mem_base + pd->dag_mem_bottom);

		u_char *dp = ((u_char *)header); /* + dag_record_size; */
		unsigned short rlen;

		/*
		 * Has "pcap_breakloop()" been called?
		 */
		if (p->break_loop) {
			/*
			 * Yes - clear the flag that indicates that
			 * it has, and return -2 to indicate that
			 * we were told to break out of the loop.
			 */
			p->break_loop = 0;
			return -2;
		}

		rlen = ntohs(header->rlen);
		if (rlen < dag_record_size)
		{
			strncpy(p->errbuf, "dag_read: record too small", PCAP_ERRBUF_SIZE);
			return -1;
		}
		pd->dag_mem_bottom += rlen;

		/* Count lost packets. */
        if (header->lctr) {
            if (pd->stat.ps_drop > (UINT_MAX - ntohs(header->lctr))) {
                pd->stat.ps_drop = UINT_MAX;
            } else {
                pd->stat.ps_drop += ntohs(header->lctr);
            }
		}

		num_ext_hdr = dag_erf_ext_header_count(dp, rlen);

		/* ERF encapsulation */
		/* The Extensible Record Format is not dropped for this kind of encapsulation,
		 * and will be handled as a pseudo header by the decoding application.
		 * The information carried in the ERF header and in the optional subheader (if present)
		 * could be merged with the libpcap information, to offer a better decoding.
		 * The packet length is
		 * o the length of the packet on the link (header->wlen),
		 * o plus the length of the ERF header (dag_record_size), as the length of the
		 *   pseudo header will be adjusted during the decoding,
		 * o plus the length of the optional subheader (if present).
		 *
		 * The capture length is header.rlen and the byte stuffing for alignment will be dropped
		 * if the capture length is greater than the packet length.
		 */
		if (p->linktype == DLT_ERF) {
			packet_len = ntohs(header->wlen) + dag_record_size;
			caplen = rlen;
			switch ((header->type & 0x7f)) {
			case TYPE_ETH:
				packet_len += 2; /* ETH header */
				break;
			} /* switch type */

			/* Include ERF extension headers */
			packet_len += (8 * num_ext_hdr);

			if (caplen > packet_len) {
				caplen = packet_len;
			}
		} else {
			/* Other kind of encapsulation according to the header Type */

			/* Skip over generic ERF header */
			dp += dag_record_size;
			/* Skip over extension headers */
			dp += 8 * num_ext_hdr;

			switch((header->type & 0x7f)) {
			case TYPE_ETH:
				packet_len = ntohs(header->wlen);
				packet_len -= (pd->dag_fcs_bits >> 3);
				caplen = rlen - dag_record_size - 2;
				/* Skip over extension headers */
				caplen -= (8 * num_ext_hdr);
				if (caplen > packet_len) {
					caplen = packet_len;
				}
				dp += 2;
				break;

			default:
				/* Unhandled ERF type.
				 * Ignore rather than generating error
				 */
				continue;
			} /* switch type */

		} /* ERF encapsulation */

		if (caplen > p->snapshot)
			caplen = p->snapshot;

		/* Run the packet filter if there is one. */
		if ((p->fcode.bf_insns == NULL) || bpf_filter(p->fcode.bf_insns, dp, packet_len, caplen)) {

			/* convert between timestamp formats */
			register unsigned long long ts;

			if (IS_BIGENDIAN()) {
				ts = SWAPLL(header->ts);
			} else {
				ts = header->ts;
			}

			switch (p->opt.tstamp_precision) {
			case PCAP_TSTAMP_PRECISION_NANO:
			default:
				ticks_per_second = 1000000000;
				break;
			}
			pcap_header.ts.tv_sec = ts >> 32;
			ts = (ts & 0xffffffffULL) * ticks_per_second;
			ts += 0x80000000; /* rounding */
			pcap_header.ts.tv_usec = ts >> 32;
			if (pcap_header.ts.tv_usec >= ticks_per_second) {
				pcap_header.ts.tv_usec -= ticks_per_second;
				pcap_header.ts.tv_sec++;
			}

			/* Fill in our own header data */
			pcap_header.caplen = caplen;
			pcap_header.len = packet_len;

			/* Count the packet. */
			pd->stat.ps_recv++;

			/* Call the user supplied callback function */
			callback(user, &pcap_header, dp);

			/* Only count packets that pass the filter, for consistency with standard Linux behaviour. */
			processed++;
			if (processed == cnt && !PACKET_COUNT_IS_UNLIMITED(cnt))
			{
				/* Reached the user-specified limit. */
				return cnt;
			}
		}
	}
#endif
	return processed;
}

/** nfpshm_inject - No support for packet transmission, so not supported
*/
static int
nfpshm_inject(pcap_t *p, const void *buf _U_, size_t size _U_)
{
	strlcpy(p->errbuf, "Sending packets isn't supported on NFP pcap firmwar",
	    PCAP_ERRBUF_SIZE);
	return (-1);
}

/** nfpshm_stats - Get statistics from private data
*/
static int
nfpshm_stats(pcap_t *p, struct pcap_stat *ps) {
	struct pcap_nfpshm *pd = p->priv;
	*ps = pd->stat;

	return 0;
}

/** nfpshm_activate - Open an NFP SHM capture device
 */
static int
nfpshm_activate(pcap_t *p)
{
	struct pcap_nfpshm *pd = p->priv;
	char *s;
	int n;
    struct nfp_ipc_client_desc nfp_ipc_client_desc;

    pd->ifup = 0;
    fprintf(stderr,"%s\n",__func__);
    if (nfpshm_alloc_shm(pd)<0) {
        fprintf(stderr, "Failed to allocate NFP SHM - is server running?\n");
        goto fail;
    }

    nfp_ipc_client_desc.name = "libpcap";
    pd->nfp_ipc_client = nfp_ipc_start_client(pd->nfp_ipc, &nfp_ipc_client_desc);
    if (pd->nfp_ipc_client < 0) {
        fprintf(stderr, "Failed to connect to pktgen SHM - is correct server running?\n");
        goto fail;
    }

    nfpshm_add(pd);

    pd->msg_sent = 0;
    pd->ifup = 1;
    pd->current_buffer = -1;
    pd->next_buffer = -1;
    pd->next_pkt = 0;
    pd->buffers_to_recycle[0] = -1;
    pd->buffers_to_recycle[1] = -1;
    pd->msg = nfp_ipc_alloc_msg(pd->nfp_ipc, sizeof(struct pktgen_ipc_msg));
    pd->pktgen_msg = (struct pktgen_ipc_msg *)(&pd->msg->data[0]);

    /* Note that no FCS will be supplied. */
    p->linktype_ext = LT_FCS_DATALINK_EXT(0);

    p->linktype = DLT_EN10MB;
	p->bufsize = 0;
	p->selectable_fd = -1;

	p->read_op = nfpshm_read;
	p->inject_op = nfpshm_inject;
	p->setfilter_op = nfpshm_setfilter;
	p->setdirection_op = NULL; /* Not implemented.*/
	p->set_datalink_op = nfpshm_set_datalink;
	p->getnonblock_op  = nfpshm_getnonblock;
	p->setnonblock_op  = nfpshm_setnonblock;
	p->stats_op        = nfpshm_stats;
	p->cleanup_op = nfpshm_cleanup;
	pd->stat.ps_drop = 0;
	pd->stat.ps_recv = 0;
	pd->stat.ps_ifdrop = 0;
	return 0;

fail:
	pcap_cleanup_live_common(p);

	return PCAP_ERROR;
}

/** nfpshm_create - Create a PCAP instance for an NFP SHM if device name matches
*/
pcap_t *nfpshm_create(const char *device, char *ebuf, int *is_ours)
{
	const char *cp;
	char *cpend;
	long devnum;
	pcap_t *p;

	/* Does this look like an NFP SHM device? */
	cp = strrchr(device, '/');
	if (cp == NULL)
		cp = device;
	/* Does it begin with "nfpshm"? */
	if (strncmp(cp, "nfpshm", 6) != 0) {
		/* Nope, doesn't begin with "nfpshm" */
		*is_ours = 0;
		return NULL;
	}
	cp += 6;
	if (cp[0] != '\0') {
		/* Not followed by a number. */
		*is_ours = 0;
		return NULL;
	}

	/* OK, it's probably ours. */
	*is_ours = 1;

	p = pcap_create_common(device, ebuf, sizeof (struct pcap_nfpshm));
	if (p == NULL)
		return NULL;

	p->activate_op = nfpshm_activate;

	/*
	 * We claim that we support nanosecond timestamps
	 */
	p->tstamp_precision_count = 1;
	p->tstamp_precision_list = malloc(1 * sizeof(u_int));
	if (p->tstamp_precision_list == NULL) {
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "malloc: %s",
		    pcap_strerror(errno));
		pcap_close(p);
		return NULL;
	}
	p->tstamp_precision_list[0] = PCAP_TSTAMP_PRECISION_NANO;
	return p;
}

/** nfpshm_findalldevs - Add list of NFP SHM interfaces that can be created
*/
int
nfpshm_findalldevs(pcap_if_t **devlistp, char *errbuf)
{
	int ret = 0;
    if (pcap_add_if(devlistp, "nfpshm", 0, "NFP SHM", errbuf) == -1) {
        ret = -1;
    }
    return ret;
}

