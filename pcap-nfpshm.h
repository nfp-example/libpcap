/*
 * pcap-nfpshm.h: Packet capture interface for NFP shared memory pcap firmware
 *
 * The functionality of this code attempts to mimic that of pcap-linux as much
 * as possible.  This code is only needed when compiling in the NFP SHM code
 * at the same time as another type of device.
 *
 * Author: Gavin Stark (gavin.stark AT netronome.com)
 */

pcap_t *nfpshm_create(const char *, char *, int *);
int nfpshm_findalldevs(pcap_if_t **devlistp, char *errbuf);

