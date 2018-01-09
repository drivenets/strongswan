/*
 * Copyright (C) 2012-2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.  *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#define _GNU_SOURCE
#include "kernel_libipsec_cheetah_ipsec.h"

#include <library.h>
#include <ipsec.h>
#include <daemon.h>
#include <networking/tun_device.h>
#include <threading/mutex.h>
#include <threading/condvar.h>
#include <threading/thread.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <utils/debug.h>
#include "kernel_libipsec_cheetah_router.h"
#include "qpb.pb-c.h"
#include "ipsec.pb-c.h"
#include "nanoserver.pb-c.h"
#include "nano_server.h"

typedef struct private_kernel_libipsec_cheetah_ipsec_t private_kernel_libipsec_cheetah_ipsec_t;
typedef struct kernel_algorithm_t kernel_algorithm_t;

/**
 * Mapping of IKEv2 kernel identifier to linux crypto API names
 */
struct kernel_algorithm_t {
	/**
	 * Identifier specified in IKEv2
	 */
	int ikev2;

	/**
	 * Name of the algorithm in linux crypto API
	 */
	const char *name;
};

/**
 * Algorithms for encryption
 */
static kernel_algorithm_t encryption_algs[] = {
/*	{ENCR_DES_IV64,				"***"				}, */
	{ENCR_DES,					"des"				},
	{ENCR_3DES,					"des3_ede"			},
/*	{ENCR_RC5,					"***"				}, */
/*	{ENCR_IDEA,					"***"				}, */
	{ENCR_CAST,					"cast5"				},
	{ENCR_BLOWFISH,				"blowfish"			},
/*	{ENCR_3IDEA,				"***"				}, */
/*	{ENCR_DES_IV32,				"***"				}, */
	{ENCR_NULL,					"cipher_null"		},
	{ENCR_AES_CBC,				"aes"				},
	{ENCR_AES_CTR,				"rfc3686(ctr(aes))"	},
	{ENCR_AES_CCM_ICV8,			"rfc4309(ccm(aes))"	},
	{ENCR_AES_CCM_ICV12,		"rfc4309(ccm(aes))"	},
	{ENCR_AES_CCM_ICV16,		"rfc4309(ccm(aes))"	},
	{ENCR_AES_GCM_ICV8,			"rfc4106(gcm(aes))"	},
	{ENCR_AES_GCM_ICV12,		"rfc4106(gcm(aes))"	},
	{ENCR_AES_GCM_ICV16,		"rfc4106(gcm(aes))"	},
	{ENCR_NULL_AUTH_AES_GMAC,	"rfc4543(gcm(aes))"	},
	{ENCR_CAMELLIA_CBC,			"cbc(camellia)"		},
/*	{ENCR_CAMELLIA_CTR,			"***"				}, */
/*	{ENCR_CAMELLIA_CCM_ICV8,	"***"				}, */
/*	{ENCR_CAMELLIA_CCM_ICV12,	"***"				}, */
/*	{ENCR_CAMELLIA_CCM_ICV16,	"***"				}, */
	{ENCR_SERPENT_CBC,			"serpent"			},
	{ENCR_TWOFISH_CBC,			"twofish"			},
	{ENCR_CHACHA20_POLY1305,	"rfc7539esp(chacha20,poly1305)"},
};

/**
 * Algorithms for integrity protection
 */
static kernel_algorithm_t integrity_algs[] = {
	{AUTH_HMAC_MD5_96,			"md5"				},
	{AUTH_HMAC_MD5_128,			"hmac(md5)"			},
	{AUTH_HMAC_SHA1_96,			"sha1"				},
	{AUTH_HMAC_SHA1_160,		"hmac(sha1)"		},
	{AUTH_HMAC_SHA2_256_96,		"sha256"			},
	{AUTH_HMAC_SHA2_256_128,	"hmac(sha256)"		},
	{AUTH_HMAC_SHA2_384_192,	"hmac(sha384)"		},
	{AUTH_HMAC_SHA2_512_256,	"hmac(sha512)"		},
/*	{AUTH_DES_MAC,				"***"				}, */
/*	{AUTH_KPDK_MD5,				"***"				}, */
	{AUTH_AES_XCBC_96,			"xcbc(aes)"			},
	{AUTH_AES_CMAC_96,			"cmac(aes)"			},
};

/**
 * Algorithms for IPComp
 */
static kernel_algorithm_t compression_algs[] = {
/*	{IPCOMP_OUI,				"***"				}, */
	{IPCOMP_DEFLATE,			"deflate"			},
	{IPCOMP_LZS,				"lzs"				},
	{IPCOMP_LZJH,				"lzjh"				},
};

/**
 * Look up a kernel algorithm name and its key size
 */
static const char* lookup_algorithm(transform_type_t type, int ikev2)
{
	kernel_algorithm_t *list;
	int i, count;
	char *name;

	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			list = encryption_algs;
			count = countof(encryption_algs);
			break;
		case INTEGRITY_ALGORITHM:
			list = integrity_algs;
			count = countof(integrity_algs);
			break;
		case COMPRESSION_ALGORITHM:
			list = compression_algs;
			count = countof(compression_algs);
			break;
		default:
			return NULL;
	}
	for (i = 0; i < count; i++)
	{
		if (list[i].ikev2 == ikev2)
		{
			return list[i].name;
		}
	}
	if (charon->kernel->lookup_algorithm(charon->kernel, ikev2, type, NULL,
										 &name))
	{
		return name;
	}
	return NULL;
}

struct private_kernel_libipsec_cheetah_ipsec_t {

	/**
	 * Public libipsec_ipsec interface
	 */
	kernel_libipsec_cheetah_ipsec_t public;

	/**
	 * Listener for lifetime expire events
	 */
	ipsec_event_listener_t ipsec_listener;

	/**
	 * Mutex to lock access to various lists
	 */
	mutex_t *mutex;

	/**
	 * List of installed policies (policy_entry_t)
	 */
	linked_list_t *policies;

	/**
	 * List of exclude routes (exclude_route_t)
	 */
	linked_list_t *excludes;

	/**
	 * Whether the remote TS may equal the IKE peer
	 */
	bool allow_peer_ts;

	//@@@ hagai start
	struct nm_transport_socket* nm_socket;
	thread_t* nm_thread;
	mutex_t*  nm_mutex;
	condvar_t* nm_condvar;
	//@@@ hagai end

};

typedef struct exclude_route_t exclude_route_t;

/**
 * Exclude route definition
 */
struct exclude_route_t {
	/** Destination address to exclude */
	host_t *dst;
	/** Source address for route */
	host_t *src;
	/** Nexthop exclude has been installed */
	host_t *gtw;
	/** References to this route */
	int refs;
};

/**
 * Clean up an exclude route entry
 */
static void exclude_route_destroy(exclude_route_t *this)
{
	this->dst->destroy(this->dst);
	this->src->destroy(this->src);
	this->gtw->destroy(this->gtw);
	free(this);
}

CALLBACK(exclude_route_match, bool,
	exclude_route_t *current, va_list args)
{
	host_t *dst;

	VA_ARGS_VGET(args, dst);
	return dst->ip_equals(dst, current->dst);
}

typedef struct route_entry_t route_entry_t;

/**
 * Installed routing entry
 */
struct route_entry_t {
	/** Name of the interface the route is bound to */
	char *if_name;
	/** Source IP of the route */
	host_t *src_ip;
	/** Gateway of the route */
	host_t *gateway;
	/** Destination net */
	chunk_t dst_net;
	/** Destination net prefixlen */
	uint8_t prefixlen;
	/** Reference to exclude route, if any */
	exclude_route_t *exclude;
};

/**
 * Destroy a route_entry_t object
 */
static void route_entry_destroy(route_entry_t *this)
{
	free(this->if_name);
	DESTROY_IF(this->src_ip);
	DESTROY_IF(this->gateway);
	chunk_free(&this->dst_net);
	free(this);
}

/**
 * Compare two route_entry_t objects
 */
static bool route_entry_equals(route_entry_t *a, route_entry_t *b)
{
	if ((!a->src_ip && !b->src_ip) || (a->src_ip && b->src_ip &&
		  a->src_ip->ip_equals(a->src_ip, b->src_ip)))
	{
		if ((!a->gateway && !b->gateway) || (a->gateway && b->gateway &&
			  a->gateway->ip_equals(a->gateway, b->gateway)))
		{
			return a->if_name && b->if_name && streq(a->if_name, b->if_name) &&
				   chunk_equals(a->dst_net, b->dst_net) &&
				   a->prefixlen == b->prefixlen;
		}
	}
	return FALSE;
}

typedef struct policy_entry_t policy_entry_t;

/**
 * Installed policy
 */
struct policy_entry_t {
	/** Direction of this policy: in, out, forward */
	uint8_t direction;
	/** Parameters of installed policy */
	struct {
		/** Subnet and port */
		host_t *net;
		/** Subnet mask */
		uint8_t mask;
		/** Protocol */
		uint8_t proto;
	} src, dst;
	/** Associated route installed for this policy */
	route_entry_t *route;
	/** References to this policy */
	int refs;
};

/**
 * Create a policy_entry_t object
 */
static policy_entry_t *create_policy_entry(traffic_selector_t *src_ts,
										   traffic_selector_t *dst_ts,
										   policy_dir_t dir)
{
	policy_entry_t *this;
	INIT(this,
		.direction = dir,
	);

	src_ts->to_subnet(src_ts, &this->src.net, &this->src.mask);
	dst_ts->to_subnet(dst_ts, &this->dst.net, &this->dst.mask);

	/* src or dest proto may be "any" (0), use more restrictive one */
	this->src.proto = max(src_ts->get_protocol(src_ts),
						  dst_ts->get_protocol(dst_ts));
	this->src.proto = this->src.proto ? this->src.proto : 0;
	this->dst.proto = this->src.proto;
	return this;
}

/**
 * Destroy a policy_entry_t object
 */
static void policy_entry_destroy(policy_entry_t *this)
{
	if (this->route)
	{
		route_entry_destroy(this->route);
	}
	DESTROY_IF(this->src.net);
	DESTROY_IF(this->dst.net);
	free(this);
}

//@@@ hagai start
static void ts2_l3prefix(traffic_selector_t* ts, Qpb__L3Prefix *subnet)
{
	host_t *net_host;
	chunk_t net_chunk;
	uint8_t mask;

	ts->to_subnet(ts, &net_host, &mask);
	subnet->length = mask;
	net_chunk = net_host->get_address(net_host);
	subnet->bytes.len = net_chunk.len;
	subnet->bytes.data = (uint8_t*)malloc(net_chunk.len);
	memcpy(subnet->bytes.data, net_chunk.ptr, net_chunk.len);
	net_host->destroy(net_host);
}

static void set_proto_address(
		host_t* host,
		Qpb__L3Address* msg_addr,
		Qpb__Ipv4Address* proto_addr4,
		Qpb__Ipv6Address* proto_addr6,
		Qpb__AddressFamily* family)
{
	switch (host->get_family(host))
	{
		case AF_INET:
		{
			struct sockaddr_in* sockaddr = (struct sockaddr_in*)(host->get_sockaddr(host));
			msg_addr->v4 = proto_addr4;
			msg_addr->v4->value = sockaddr->sin_addr.s_addr;
			*family = QPB__ADDRESS_FAMILY__IPV4;
		}
		break;

		case AF_INET6:
		{
			struct sockaddr_in6* sockaddr = (struct sockaddr_in6*)(host->get_sockaddr(host));
			msg_addr->v6 = proto_addr6;
			msg_addr->v6->bytes.len = 16;
			msg_addr->v6->bytes.data = (uint8_t*)malloc(msg_addr->v6->bytes.len);
			memcpy(msg_addr->v6->bytes.data,
					sockaddr->sin6_addr.s6_addr, msg_addr->v6->bytes.len);
			*family = QPB__ADDRESS_FAMILY__IPV6;
		}
		break;
	}

}
//@@@ hagai end

CALLBACK(policy_entry_equals, bool,
	policy_entry_t *a, va_list args)
{
	policy_entry_t *b;

	VA_ARGS_VGET(args, b);
	return a->direction == b->direction &&
		   a->src.proto == b->src.proto &&
		   a->dst.proto == b->dst.proto &&
		   a->src.mask == b->src.mask &&
		   a->dst.mask == b->dst.mask &&
		   a->src.net->equals(a->src.net, b->src.net) &&
		   a->dst.net->equals(a->dst.net, b->dst.net);
}

/**
 * Expiration callback
 */
static void expire(uint8_t protocol, uint32_t spi, host_t *dst, bool hard)
{
	charon->kernel->expire(charon->kernel, protocol, spi, dst, hard);
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_kernel_libipsec_cheetah_ipsec_t *this)
{
	//@@@ hagai return KERNEL_REQUIRE_UDP_ENCAPSULATION | KERNEL_ESP_V3_TFC;
	return KERNEL_ESP_V3_TFC;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, host_t *src, host_t *dst,
	uint8_t protocol, uint32_t *spi)
{
	return ipsec->sas->get_spi(ipsec->sas, src, dst, protocol, spi);
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, host_t *src, host_t *dst,
	uint16_t *cpi)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_add_sa_t *data)
{
	/*@@@ hagai udp encapsulation hack
	int ret = ipsec->sas->add_sa(ipsec->sas, id->src, id->dst, id->spi, id->proto,
					data->reqid, id->mark, data->tfc, data->lifetime,
					data->enc_alg, data->enc_key, data->int_alg, data->int_key,
					data->mode, data->ipcomp, data->cpi, data->initiator,
					data->encap, data->esn, data->inbound, data->update);
	*/

	DBG1(DBG_KNL, "add_sa start. spi=%x", id->spi);
	int ret = ipsec->sas->add_sa(ipsec->sas, id->src, id->dst, id->spi, id->proto,
					data->reqid, id->mark, data->tfc, data->lifetime,
					data->enc_alg, data->enc_key, data->int_alg, data->int_key,
					data->mode, data->ipcomp, data->cpi, data->initiator,
					1, data->esn, data->inbound, data->update);

	DBG1(DBG_KNL, "add_sa ret=%d", ret);
	if (ret != SUCCESS)
		return ret;


	//@@@ hagai start
	Cheetah__CheetahMessage encap = CHEETAH__CHEETAH_MESSAGE__INIT;
	Ipsec__Message ipsec_msg = IPSEC__MESSAGE__INIT;

	encap.ipsec = &ipsec_msg;
	encap.message_case = CHEETAH__CHEETAH_MESSAGE__MESSAGE_IPSEC;
	ipsec_msg.type = IPSEC__MESSAGE__TYPE__ADD_SA;

	Ipsec__AddSA ipsec_add_sa_msg = IPSEC__ADD_SA__INIT;
	Qpb__L3Address src = QPB__L3_ADDRESS__INIT;
	Qpb__L3Prefix src_subnet = QPB__L3_PREFIX__INIT;
	Qpb__Ipv4Address src_addr4 = QPB__IPV4_ADDRESS__INIT;
	Qpb__Ipv6Address src_addr6 = QPB__IPV6_ADDRESS__INIT;

	Qpb__L3Address dst = QPB__L3_ADDRESS__INIT;
	Qpb__L3Prefix dst_subnet = QPB__L3_PREFIX__INIT;
	Qpb__Ipv4Address dst_addr4 = QPB__IPV4_ADDRESS__INIT;
	Qpb__Ipv6Address dst_addr6 = QPB__IPV6_ADDRESS__INIT;

	ipsec_msg.add_sa = &ipsec_add_sa_msg;

	ipsec_add_sa_msg.spi = id->spi;
	ipsec_add_sa_msg.src = &src;
	ipsec_add_sa_msg.dst = &dst;

	set_proto_address(id->src, ipsec_add_sa_msg.src, &src_addr4, &src_addr6, &ipsec_add_sa_msg.src_family);
	set_proto_address(id->dst, ipsec_add_sa_msg.dst, &dst_addr4, &dst_addr6, &ipsec_add_sa_msg.dst_family);

	traffic_selector_t *first_src_ts, *first_dst_ts;

	data->src_ts->get_first(data->src_ts, (void**)&first_src_ts);
	data->dst_ts->get_first(data->dst_ts, (void**)&first_dst_ts);

	ipsec_add_sa_msg.src_subnet = &src_subnet;
	ts2_l3prefix(first_src_ts, ipsec_add_sa_msg.src_subnet);

	ipsec_add_sa_msg.dst_subnet = &dst_subnet;
	ts2_l3prefix(first_dst_ts, ipsec_add_sa_msg.dst_subnet);

	ipsec_add_sa_msg.inbound = data->inbound;
	ipsec_add_sa_msg.udp_encapsulation = data->encap;

	const char *enc_alg_name = lookup_algorithm(ENCRYPTION_ALGORITHM, data->enc_alg);
	DBG2(DBG_KNL, "  using encryption algorithm %N with key size %d",
		 encryption_algorithm_names, data->enc_alg,
		 data->enc_key.len * 8);

	ipsec_add_sa_msg.enc_alg_name = strdup(enc_alg_name);
	ipsec_add_sa_msg.enc_key.len = data->enc_key.len;
	ipsec_add_sa_msg.enc_key.data = (uint8_t *)malloc(ipsec_add_sa_msg.enc_key.len);
	memcpy(ipsec_add_sa_msg.enc_key.data, data->enc_key.ptr, data->enc_key.len);

	const char* auth_alg_name = lookup_algorithm(INTEGRITY_ALGORITHM, data->int_alg);
	ipsec_add_sa_msg.auth_alg_name = strdup(auth_alg_name);
	ipsec_add_sa_msg.auth_key.len = data->int_key.len;
	ipsec_add_sa_msg.auth_key.data = (uint8_t *)malloc(ipsec_add_sa_msg.auth_key.len);
	memcpy(ipsec_add_sa_msg.auth_key.data, data->int_key.ptr, ipsec_add_sa_msg.auth_key.len);

	void						*buf;
	unsigned					buf_len;
	int							res;

	buf_len = cheetah__cheetah_message__get_packed_size(&encap);
	buf = malloc(buf_len);
	cheetah__cheetah_message__pack(&encap, buf);

	DBG1(DBG_KNL, "sending add_sa to cheetah. socket=%x, session=%lu, buf_len=%d", this->nm_socket, this->nm_socket->session_id, buf_len);
	res = nm_transport_send_data(this->nm_socket, buf, buf_len);
	DBG1(DBG_KNL, "sa_send result=%d, errno=%d", res, errno);
	free(buf);

	return SUCCESS;
	//@@@ hagai end
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_update_sa_t *data)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
	time_t *time)
{
	return ipsec->sas->query_sa(ipsec->sas, id->src, id->dst, id->spi,
								id->proto, id->mark, bytes, packets, time);
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	kernel_ipsec_del_sa_t *data)
{
	DBG1(DBG_KNL, "del_sa start. spi=%x", id->spi);

	int ret = ipsec->sas->del_sa(ipsec->sas, id->src, id->dst, id->spi, id->proto,
							  data->cpi, id->mark);
	DBG1(DBG_KNL, "del_sa. ret=%d", ret);
	if (ret != SUCCESS)
		return ret;

	//@@@ hagai start
	Cheetah__CheetahMessage encap = CHEETAH__CHEETAH_MESSAGE__INIT;
	Ipsec__Message ipsec_msg = IPSEC__MESSAGE__INIT;

	//@@@ hagai some code duplication with the add_sa method. consider revising.
	encap.ipsec = &ipsec_msg;
	encap.message_case = CHEETAH__CHEETAH_MESSAGE__MESSAGE_IPSEC;
	ipsec_msg.type = IPSEC__MESSAGE__TYPE__DELETE_SA;

	Ipsec__DeleteSA ipsec_delete_sa_msg = IPSEC__DELETE_SA__INIT;
	ipsec_delete_sa_msg.spi = id->spi;
	ipsec_msg.delete_sa = &ipsec_delete_sa_msg;

	void						*buf;
	unsigned					buf_len;
	int							res;

	buf_len = cheetah__cheetah_message__get_packed_size(&encap);
	buf = malloc(buf_len);
	cheetah__cheetah_message__pack(&encap, buf);

	DBG1(DBG_KNL, "sending delete_sa to cheetah. socket=%x, session=%lu, buf_len=%d", this->nm_socket, this->nm_socket->session_id, buf_len);
	res = nm_transport_send_data(this->nm_socket, buf, buf_len);
	DBG1(DBG_KNL, "sa_send result=%d, errno=%d", res, errno);
	free(buf);

	//@@@ hagai end
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this)
{
	//@@@ hagai do we need this? return ipsec->sas->flush_sas(ipsec->sas);
	return SUCCESS;
}

/**
 * Add an explicit exclude route to a routing entry
 */
static void add_exclude_route(private_kernel_libipsec_cheetah_ipsec_t *this,
							  route_entry_t *route, host_t *src, host_t *dst)
{
	exclude_route_t *exclude;
	host_t *gtw;

	if (this->excludes->find_first(this->excludes, exclude_route_match,
								  (void**)&exclude, dst))
	{
		route->exclude = exclude;
		exclude->refs++;
	}

	if (!route->exclude)
	{
		DBG2(DBG_KNL, "installing new exclude route for %H src %H", dst, src);
		gtw = charon->kernel->get_nexthop(charon->kernel, dst, -1, NULL, NULL);
		if (gtw)
		{
			char *if_name = NULL;

			if (charon->kernel->get_interface(charon->kernel, src, &if_name) &&
				charon->kernel->add_route(charon->kernel, dst->get_address(dst),
									dst->get_family(dst) == AF_INET ? 32 : 128,
									gtw, src, if_name) == SUCCESS)
			{
				INIT(exclude,
					.dst = dst->clone(dst),
					.src = src->clone(src),
					.gtw = gtw->clone(gtw),
					.refs = 1,
				);
				route->exclude = exclude;
				this->excludes->insert_last(this->excludes, exclude);
			}
			else
			{
				DBG1(DBG_KNL, "installing exclude route for %H failed", dst);
			}
			gtw->destroy(gtw);
			free(if_name);
		}
		else
		{
			DBG1(DBG_KNL, "gateway lookup for %H failed", dst);
		}
	}
}

/**
 * Remove an exclude route attached to a routing entry
 */
static void remove_exclude_route(private_kernel_libipsec_cheetah_ipsec_t *this,
								 route_entry_t *route)
{
	char *if_name = NULL;
	host_t *dst;

	if (!route->exclude || --route->exclude->refs > 0)
	{
		return;
	}
	this->excludes->remove(this->excludes, route->exclude, NULL);

	dst = route->exclude->dst;
	DBG2(DBG_KNL, "uninstalling exclude route for %H src %H",
		 dst, route->exclude->src);
	if (charon->kernel->get_interface(charon->kernel, route->exclude->src,
									  &if_name) &&
		charon->kernel->del_route(charon->kernel, dst->get_address(dst),
								  dst->get_family(dst) == AF_INET ? 32 : 128,
								  route->exclude->gtw, route->exclude->src,
								  if_name) != SUCCESS)
	{
		DBG1(DBG_KNL, "uninstalling exclude route for %H failed", dst);
	}
	exclude_route_destroy(route->exclude);
	route->exclude = NULL;
	free(if_name);
}

/**
 * Install a route for the given policy
 *
 * this->mutex is released by this function
 */
static bool install_route(private_kernel_libipsec_cheetah_ipsec_t *this,
	host_t *src, host_t *dst, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_entry_t *policy)
{
	route_entry_t *route, *old;
	host_t *src_ip;
	bool is_virtual;

	if (policy->direction != POLICY_OUT)
	{
		this->mutex->unlock(this->mutex);
		return TRUE;
	}

	if (charon->kernel->get_address_by_ts(charon->kernel, src_ts, &src_ip,
										  &is_virtual) != SUCCESS)
	{
		traffic_selector_t *multicast, *broadcast = NULL;
		bool ignore = FALSE;

		this->mutex->unlock(this->mutex);
		switch (src_ts->get_type(src_ts))
		{
			case TS_IPV4_ADDR_RANGE:
				multicast = traffic_selector_create_from_cidr("224.0.0.0/4",
															  0, 0, 0xffff);
				broadcast = traffic_selector_create_from_cidr("255.255.255.255/32",
															  0, 0, 0xffff);
				break;
			case TS_IPV6_ADDR_RANGE:
				multicast = traffic_selector_create_from_cidr("ff00::/8",
															  0, 0, 0xffff);
				break;
			default:
				return FALSE;
		}
		ignore = src_ts->is_contained_in(src_ts, multicast);
		ignore |= broadcast && src_ts->is_contained_in(src_ts, broadcast);
		multicast->destroy(multicast);
		DESTROY_IF(broadcast);
		if (!ignore)
		{
			DBG1(DBG_KNL, "error installing route with policy %R === %R %N",
				 src_ts, dst_ts, policy_dir_names, policy->direction);
		}
		return ignore;
	}

	INIT(route,
		.if_name = router->get_tun_name(router, is_virtual ? src_ip : NULL),
		.src_ip = src_ip,
		.dst_net = chunk_clone(policy->dst.net->get_address(policy->dst.net)),
		.prefixlen = policy->dst.mask,
	);
#ifndef __linux__
	/* on Linux we cant't install a gateway */
	route->gateway = charon->kernel->get_nexthop(charon->kernel, dst, -1, src,
												 NULL);
#endif

	if (policy->route)
	{
		old = policy->route;

		if (route_entry_equals(old, route))
		{	/* such a route already exists */
			route_entry_destroy(route);
			this->mutex->unlock(this->mutex);
			return TRUE;
		}
		/* uninstall previously installed route */
		//@@@ hagai
#if 0
		if (charon->kernel->del_route(charon->kernel, old->dst_net,
									  old->prefixlen, old->gateway,
									  old->src_ip, old->if_name) != SUCCESS)
		{
			DBG1(DBG_KNL, "error uninstalling route installed with policy "
				 "%R === %R %N", src_ts, dst_ts, policy_dir_names,
				 policy->direction);
		}
#endif
		route_entry_destroy(old);
		policy->route = NULL;
	}

	if (!this->allow_peer_ts && dst_ts->is_host(dst_ts, dst))
	{
		DBG1(DBG_KNL, "can't install route for %R === %R %N, conflicts with "
			 "IKE traffic", src_ts, dst_ts, policy_dir_names,
			 policy->direction);
		route_entry_destroy(route);
		this->mutex->unlock(this->mutex);
		return FALSE;
	}
	/* if remote traffic selector covers the IKE peer, add an exclude route */
	if (!this->allow_peer_ts && dst_ts->includes(dst_ts, dst))
	{
		/* add exclude route for peer */
		add_exclude_route(this, route, src, dst);
	}

	//@@@ hagai
	return TRUE;
#if 0
	DBG2(DBG_KNL, "installing route: %R src %H dev %s",
		 dst_ts, route->src_ip, route->if_name);

	switch (charon->kernel->add_route(charon->kernel, route->dst_net,
									  route->prefixlen, route->gateway,
									  route->src_ip, route->if_name))
	{
		case ALREADY_DONE:
			/* route exists, do not uninstall */
			remove_exclude_route(this, route);
			route_entry_destroy(route);
			this->mutex->unlock(this->mutex);
			return TRUE;
		case SUCCESS:
			/* cache the installed route */
			policy->route = route;
			this->mutex->unlock(this->mutex);
			return TRUE;
		default:
			DBG1(DBG_KNL, "installing route failed: %R src %H dev %s",



				 dst_ts, route->src_ip, route->if_name);
			remove_exclude_route(this, route);
			route_entry_destroy(route);
			this->mutex->unlock(this->mutex);
			return FALSE;
	}
#endif
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	policy_entry_t *policy, *found = NULL;
	status_t status;

	status = ipsec->policies->add_policy(ipsec->policies, data->src, data->dst,
										 id->src_ts, id->dst_ts, id->dir,
										 data->type, data->sa, id->mark,
										 data->prio);
	if (status != SUCCESS)
	{
		return status;
	}
	/* we track policies in order to install routes */
	policy = create_policy_entry(id->src_ts, id->dst_ts, id->dir);

	this->mutex->lock(this->mutex);
	if (this->policies->find_first(this->policies, policy_entry_equals,
								  (void**)&found, policy))
	{
		policy_entry_destroy(policy);
		policy = found;
	}
	else
	{	/* use the new one, if we have no such policy */
		this->policies->insert_last(this->policies, policy);
	}
	policy->refs++;

	if (!install_route(this, data->src, data->dst, id->src_ts, id->dst_ts,
					   policy))
	{
		return FAILED;
	}
	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this, kernel_ipsec_policy_id_t *id,
	kernel_ipsec_manage_policy_t *data)
{
	policy_entry_t *policy, *found = NULL;
	status_t status;

	status = ipsec->policies->del_policy(ipsec->policies, data->src, data->dst,
										 id->src_ts, id->dst_ts, id->dir,
										 data->type, data->sa, id->mark,
										 data->prio);

	policy = create_policy_entry(id->src_ts, id->dst_ts, id->dir);

	this->mutex->lock(this->mutex);
	if (!this->policies->find_first(this->policies, policy_entry_equals,
									(void**)&found, policy))
	{
		policy_entry_destroy(policy);
		this->mutex->unlock(this->mutex);
		return status;
	}
	policy_entry_destroy(policy);
	policy = found;

	if (--policy->refs > 0)
	{	/* policy is still in use */
		this->mutex->unlock(this->mutex);
		return status;
	}

	if (policy->route)
	{
		route_entry_t *route = policy->route;

		if (charon->kernel->del_route(charon->kernel, route->dst_net,
									  route->prefixlen, route->gateway,
									  route->src_ip, route->if_name) != SUCCESS)
		{
			DBG1(DBG_KNL, "error uninstalling route installed with "
				 "policy %R === %R %N", id->src_ts, id->dst_ts,
				 policy_dir_names, id->dir);
		}
		remove_exclude_route(this, route);
	}
	this->policies->remove(this->policies, policy, NULL);
	policy_entry_destroy(policy);
	this->mutex->unlock(this->mutex);
	return status;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_kernel_libipsec_cheetah_ipsec_t *this)
{
	policy_entry_t *pol;
	status_t status;

	status = ipsec->policies->flush_policies(ipsec->policies);

	this->mutex->lock(this->mutex);
	while (this->policies->remove_first(this->policies, (void*)&pol) == SUCCESS)
	{
		if (pol->route)
		{
			route_entry_t *route = pol->route;

			charon->kernel->del_route(charon->kernel, route->dst_net,
									  route->prefixlen, route->gateway,
									  route->src_ip, route->if_name);
			remove_exclude_route(this, route);
		}
		policy_entry_destroy(pol);
	}
	this->mutex->unlock(this->mutex);
	return status;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_kernel_libipsec_cheetah_ipsec_t *this, int fd, int family)
{
	/* we use exclude routes for this */
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_kernel_libipsec_cheetah_ipsec_t *this, int fd, int family, uint16_t port)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, destroy, void,
	private_kernel_libipsec_cheetah_ipsec_t *this)
{
	//@@@ hagai start
	nm_transport_stop_server(this->nm_socket);
	this->nm_condvar->destroy(this->nm_condvar);
	this->nm_mutex->destroy(this->nm_mutex);
	free(this->nm_socket);
	//@@@ hagai TODO - how to stop thread?
	//@@@ hagai end

	ipsec->events->unregister_listener(ipsec->events, &this->ipsec_listener);
	this->policies->destroy_function(this->policies, (void*)policy_entry_destroy);
	this->excludes->destroy(this->excludes);
	this->mutex->destroy(this->mutex);
	free(this);
}

//@@@ hagai start
static void channel_established_cb(void *context)
{
	private_kernel_libipsec_cheetah_ipsec_t* this =
			(private_kernel_libipsec_cheetah_ipsec_t *)context;
	this->nm_condvar->signal(this->nm_condvar);
	DBG1(DBG_KNL, "channel established with cheetah\n");
}

static void channel_disconnected_cb(void *context)
{
	DBG1(DBG_KNL, "channel disconnected with cheetah\n");
}

static void msg_received_cb(uint8_t *msg, int len, void *args)
{
	printf("msg_received_cb: message length %d\n", len);
}

static void nano_log(int i_LogLevel, char* pba_format, ...)
{
	if (NULL == pba_format)
	{
		/*
		 * The meaning of pc_log points to NULL is usage of Log function without initializing the log previously
		 * (by calling log_create function).
		 */
		return;
	}

    va_list args;
    va_start(args, pba_format);
	charon->bus->vlog(charon->bus, DBG_KNL, 1, pba_format, args);
    va_end (args);
}

static void *nano_processing_thread(void *arg)
{
	private_kernel_libipsec_cheetah_ipsec_t *this = (private_kernel_libipsec_cheetah_ipsec_t*)arg;

	thread_cancelability(TRUE); //@@@ hagai what is this?

	while (TRUE)
	{
		nm_transport_client_loop(this->nm_socket, NULL);
		usleep(100000); //@@@ hagai - tune this
	}

}

//@@@ hagai end

static int get_network_fd(pid_t pid)
{
	char buf[64];
	sprintf(buf, "/proc/%d/ns/net", pid);
	int fd = open(buf, O_RDONLY); /* Get file descriptor for namespace */

	return fd;
}

kernel_libipsec_cheetah_ipsec_t *kernel_libipsec_cheetah_ipsec_create()
{
	private_kernel_libipsec_cheetah_ipsec_t *this;

	INIT(this,
		.public = {
			.interface = {
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
		},
		.ipsec_listener = {
			.expire = expire,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.policies = linked_list_create(),
		.excludes = linked_list_create(),
		.allow_peer_ts = lib->settings->get_bool(lib->settings,
					"%s.plugins.kernel-libipsec.allow_peer_ts", FALSE, lib->ns),
	);

	ipsec->events->register_listener(ipsec->events, &this->ipsec_listener);

	//@@@ hagai teardown?
	//@@@ hagai start
	nm_transport_init_logger((logger_callback)nano_log);

	pid_t pid = getpid();
	int original_fd = get_network_fd(pid);
	int nano_fd = get_network_fd(1);

    int ret = setns (nano_fd, CLONE_NEWNET);

    this->nm_socket = (struct nm_transport_socket *)malloc(sizeof(struct nm_transport_socket));
	this->nm_socket = nm_transport_init(this->nm_socket,
			//,"tcp://0.0.0.0:7788"
			"tcp://Datapath1:2710", //@@@ todo hagai hardcoded first, then from config
			"strongswan",
			0,
			msg_received_cb,
			channel_established_cb,
			channel_disconnected_cb,
			NULL,
			this);

	if (this->nm_socket <= 0)
	{
		DBG1(DBG_KNL, "unable to create nanoserver socket");
		destroy(this);
		return NULL;
	}

	ret = setns(original_fd, CLONE_NEWNET);

	this->nm_mutex = mutex_create(MUTEX_TYPE_DEFAULT);
	this->nm_condvar = condvar_create(CONDVAR_TYPE_DEFAULT);

	// start nano processing thread
	this->nm_thread = thread_create(nano_processing_thread, this);

	DBG1(DBG_KNL, "Waiting for a connection to cheetah");

	// wait for the channel with cheetah to be established
	this->nm_condvar->wait(this->nm_condvar, this->nm_mutex);

	DBG1(DBG_KNL, "Connection with cheetah established");

	//@@@ hagai end

	return &this->public;
};
