/*
 * pcap-nfpshm.c: Packet capture interface for NFP SHM pcap firmware
 *
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

#include "pcap-nfpshm.h"

/*
 * Private data for capturing on DAG devices.
 */
struct pcap_dag {
	struct pcap_stat stat;
	void	*dag_mem_base;	/* DAG card memory base address */
	u_int	dag_mem_bottom;	/* DAG card current memory bottom offset */
	u_int	dag_mem_top;	/* DAG card current memory top offset */
	int	dag_fcs_bits;	/* Number of checksum bits from link layer */
	int	dag_stream;	/* DAG stream number */
	int	dag_timeout;	/* timeout specified to pcap_open_live.
				 * Same as in linux above, introduce
				 * generally? */
    int nonblock;
    struct nfp_ipc *nfp_ipc;
    int nfp_ipc_client;
};
struct dag_record_t
{
    int ts;
    int wlen;
    int rlen;
    int lctr;
    int type;
};

typedef struct pcap_dag_node {
	struct pcap_dag_node *next;
	pcap_t *p;
	pid_t pid;
} pcap_dag_node_t;

static pcap_dag_node_t *pcap_dags = NULL;
static int atexit_handler_installed = 0;
static const unsigned short endian_test_word = 0x0100;

#define IS_BIGENDIAN() (*((unsigned char *)&endian_test_word))

#define MAX_DAG_PACKET 65536

static unsigned char TempPkt[MAX_DAG_PACKET];

static int nfpshm_set_datalink(pcap_t *p, int dlt);

static void
delete_pcap_dag(pcap_t *p)
{
	pcap_dag_node_t *curr = NULL, *prev = NULL;

	for (prev = NULL, curr = pcap_dags; curr != NULL && curr->p != p; prev = curr, curr = curr->next) {
		/* empty */
	}

	if (curr != NULL && curr->p == p) {
		if (prev != NULL) {
			prev->next = curr->next;
		} else {
			pcap_dags = curr->next;
		}
	}
}

/*
 * Performs a graceful shutdown of the DAG card, frees dynamic memory held
 * in the pcap_t structure, and closes the file descriptor for the DAG card.
 */

static void
dag_platform_cleanup(pcap_t *p)
{
	struct pcap_dag *pd;

	if (p != NULL) {
		pd = p->priv;

        nfp_ipc_stop_client(pd->nfp_ipc, pd->nfp_ipc_client);


		if(dag_stop(p->fd) < 0)
			fprintf(stderr,"dag_stop: %s\n", strerror(errno));
		if(p->fd != -1) {
			if(dag_close(p->fd) < 0)
				fprintf(stderr,"dag_close: %s\n", strerror(errno));
			p->fd = -1;
		}
		delete_pcap_dag(p);
		pcap_cleanup_live_common(p);
	}
	/* Note: don't need to call close(p->fd) here as dag_close(p->fd) does this. */
}

static void
atexit_handler(void)
{
	while (pcap_dags != NULL) {
		if (pcap_dags->pid == getpid()) {
			dag_platform_cleanup(pcap_dags->p);
		} else {
			delete_pcap_dag(pcap_dags->p);
		}
	}
}

static int
new_pcap_dag(pcap_t *p)
{
	pcap_dag_node_t *node = NULL;

	if ((node = malloc(sizeof(pcap_dag_node_t))) == NULL) {
		return -1;
	}

	if (!atexit_handler_installed) {
		atexit(atexit_handler);
		atexit_handler_installed = 1;
	}

	node->next = pcap_dags;
	node->p = p;
	node->pid = getpid();

	pcap_dags = node;

	return 0;
}

static unsigned int
dag_erf_ext_header_count(uint8_t * erf, size_t len)
{
	uint32_t hdr_num = 0;
	uint8_t  hdr_type;

	/* basic sanity checks */
	if ( erf == NULL )
		return 0;
	if ( len < 16 )
		return 0;

	/* check if we have any extension headers */
	if ( (erf[8] & 0x80) == 0x00 )
		return 0;

	/* loop over the extension headers */
	do {

		/* sanity check we have enough bytes */
		if ( len < (24 + (hdr_num * 8)) )
			return hdr_num;

		/* get the header type */
		hdr_type = erf[(16 + (hdr_num * 8))];
		hdr_num++;

	} while ( hdr_type & 0x80 );

	return hdr_num;
}

/*
 * Installs the given bpf filter program in the given pcap structure.  There is
 * no attempt to store the filter in kernel memory as that is not supported
 * with NFP SHM pcap firmware.
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

static int
nfpshm_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
	struct pcap_dag *pd = p->priv;
    pd->nonblock = nonblock;
	return (0);
}

static int
nfpshm_getnonblock(pcap_t *p, char *errbuf)
{
	struct pcap_dag *pd = p->priv;
    return pd->nonblock;
}

static int
nfpshm_set_datalink(pcap_t *p, int dlt)
{
	p->linktype = dlt;

	return (0);
}

static int
nfpshm_get_datalink(pcap_t *p)
{
	struct pcap_dag *pd = p->priv;
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

/*
 *  Read at most max_packets from the capture stream and call the callback
 *  for each of them. Returns the number of packets handled, -1 if an
 *  error occured, or -2 if we were told to break out of the loop.
 */
static int
dag_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_dag *pd = p->priv;
	unsigned int processed = 0;
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

	return processed;
}

static int
nfpshm_inject(pcap_t *p, const void *buf _U_, size_t size _U_)
{
	strlcpy(p->errbuf, "Sending packets isn't supported on NFP pcap firmwar",
	    PCAP_ERRBUF_SIZE);
	return (-1);
}

static int
nfpshm_stats(pcap_t *p, struct pcap_stat *ps) {
	struct pcap_dag *pd = p->priv;
	*ps = pd->stat;

	return 0;
}

/*
 *  Get a handle for a live capture from the given DAG device.  Passing a NULL
 *  device will result in a failure.  The promisc flag is ignored because DAG
 *  cards are always promiscuous.  The to_ms parameter is used in setting the
 *  API polling parameters.
 *
 *  snaplen is now also ignored, until we get per-stream slen support. Set
 *  slen with approprite DAG tool BEFORE pcap_activate().
 *
 *  See also pcap(3).
 */
static int nfpshm_activate(pcap_t *p)
{
	struct pcap_dag *pd = p->priv;
	char *s;
	int n;
	daginf_t* daginf;
	char * newDev = NULL;
	char * device = p->opt.source;
    struct nfp_ipc_client_desc nfp_ipc_client_desc;

    nfp_ipc_client_desc.name = "libpcap";
    pd->nfp_ipc_client = nfp_ipc_start_client(pd->nfp_ipc, &nfp_ipc_client_desc);
    if (pd->nfp_ipc_client < 0) {
        fprintf(stderr, "Failed to connect to pktgen SHM\n");
        goto fail;
    }

        struct pktgen_ipc_msg *pktgen_msg;
        struct nfp_ipc_msg *msg;
        msg = nfp_ipc_alloc_msg(pd->nfp_ipc, sizeof(struct pktgen_ipc_msg));
        pktgen_msg = (struct pktgen_ipc_msg *)(&msg->data[0]);

	/*
	 * Find out how many FCS bits we should strip.
	 * First, query the card to see if it strips the FCS.
	 */
	daginf = dag_info(p->fd);
	if ((0x4200 == daginf->device_code) || (0x4230 == daginf->device_code))	{
		/* DAG 4.2S and 4.23S already strip the FCS.  Stripping the final word again truncates the packet. */
		pd->dag_fcs_bits = 0;

		/* Note that no FCS will be supplied. */
		p->linktype_ext = LT_FCS_DATALINK_EXT(0);
	} else {
		/*
		 * Start out assuming it's 32 bits.
		 */
		pd->dag_fcs_bits = 32;

		/* Allow an environment variable to override. */
		if ((s = getenv("ERF_FCS_BITS")) != NULL) {
			if ((n = atoi(s)) == 0 || n == 16 || n == 32) {
				pd->dag_fcs_bits = n;
			} else {
				snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
					"pcap_activate %s: bad ERF_FCS_BITS value (%d) in environment\n", device, n);
				goto failstop;
			}
		}

		/*
		 * Did the user request that they not be stripped?
		 */
		if ((s = getenv("ERF_DONT_STRIP_FCS")) != NULL) {
			/* Yes.  Note the number of bytes that will be
			   supplied. */
			p->linktype_ext = LT_FCS_DATALINK_EXT(pd->dag_fcs_bits/16);

			/* And don't strip them. */
			pd->dag_fcs_bits = 0;
		}
	}

	pd->dag_timeout	= p->opt.timeout;

	p->linktype = -1;
	if (dag_get_datalink(handle) < 0)
		goto failstop;

	p->bufsize = 0;

	if (new_pcap_dag(handle) < 0) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE, "new_pcap_dag %s: %s\n", device, pcap_strerror(errno));
		goto failstop;
	}

	/*
	 * "select()" and "poll()" don't work on DAG device descriptors.
	 */
	p->selectable_fd = -1;

	if (newDev != NULL) {
		free((char *)newDev);
	}

	p->read_op = dag_read;
	p->inject_op = nfpshm_inject;
	p->setfilter_op = nfpshm_setfilter;
	p->setdirection_op = NULL; /* Not implemented.*/
	p->set_datalink_op = nfpshm_set_datalink;
	p->getnonblock_op  = nfpshm_getnonblock;
	p->setnonblock_op  = nfpshm_setnonblock;
	p->stats_op        = nfpshm_stats;
	p->cleanup_op = dag_platform_cleanup;
	pd->stat.ps_drop = 0;
	pd->stat.ps_recv = 0;
	pd->stat.ps_ifdrop = 0;
	return 0;

failstop:
	if (dag_stop(p->fd) < 0)
		fprintf(stderr,"dag_stop: %s\n", strerror(errno));

failclose:
	if (dag_close(p->fd) < 0)
		fprintf(stderr,"dag_close: %s\n", strerror(errno));
	delete_pcap_dag(handle);

fail:
	pcap_cleanup_live_common(handle);
	if (newDev != NULL) {
		free((char *)newDev);
	}

	return PCAP_ERROR;
}

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

	p = pcap_create_common(device, ebuf, sizeof (struct pcap_dag));
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

int
nfpshm_findalldevs(pcap_if_t **devlistp, char *errbuf)
{
	int ret = 0;
    if (pcap_add_if(devlistp, "nfpshm", 0, "NFP SHM", errbuf) == -1) {
        ret = -1;
    }
    return ret;
}

