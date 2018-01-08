#include <assert.h>
#include <nanomsg/nn.h>
#include <nanomsg/pair.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include <stdarg.h>

#include "nano_server.h"
#include "nanomsg_transport.pb-c.h"


#define MAX_RECEIVED_MSG_PER_LOOP 1024
#define KEEPALIVE_INTERVAL_SECONDS 5
#define KEEPALIVE_LOSE_TOLLERANCE 5
#define NM_TRANSPORT_MAX_BUFFER_SIZE 2048

const char *send_error_strings(int value);
// default Logger for debugging
static void printf_log_msg(int log_level, const char *msg, ...)
{
	va_list args;
	va_start(args, msg);
	vprintf(msg, args);
	printf("\n");
	va_end(args);
}


static logger_callback _nn_log = &printf_log_msg;
#define nn_log(log_level, format, ...) _nn_log(log_level, "NanoSrv: " format, ##__VA_ARGS__)

void nm_transport_change_channel_state(
		struct nm_transport_socket * nm_sock, 
		enum session_state new_channel_state);

static void nanomsg_keepalive(
		struct nm_transport_socket *socket, 
		uint64_t timestamp);

int nanomsg_reset(struct nm_transport_socket *socket);



// Init logger function to change the default logger
void nm_transport_init_logger(logger_callback lcb)
{
	_nn_log = lcb;
}

void nm_transport_change_channel_state(
		struct nm_transport_socket * nm_sock, 
		enum session_state new_channel_state)
{
	enum session_state prev_state;

	if (!nm_sock){
		return;
	}

	prev_state = nm_sock->session_state;
	nm_sock->session_state = new_channel_state;

	if (prev_state != new_channel_state
			&& NM_SESSION_DOWN ==  new_channel_state){
		nm_sock->session_id++;
	}

	if (prev_state != NM_SESSION_UP
			&& new_channel_state == NM_SESSION_UP
			&& nm_sock->on_established){
		(nm_sock->on_established)(nm_sock->args);
	} else if (prev_state == NM_SESSION_UP
			&& new_channel_state != NM_SESSION_UP
			&& nm_sock->on_disconnected){
		(nm_sock->on_disconnected)(nm_sock->args);
	}
}

struct nm_transport_socket *nm_transport_init(
		struct nm_transport_socket		*nm_sock,
		const char						*addr, 
		const char						*name,
		int								is_server,
		msg_received_callback			on_msg_received,
		channel_state_changed_callback	on_established,
		channel_state_changed_callback	on_disconnected,
		should_yield_callback			check_should_yield,
		void							*args)
{
	int set_bufsize = 32 * 1024 * 1024; // Buffer sizes
	int socket_id, end_point;
	//struct nm_socket *socket;

	nn_log(LOG_INFO, "Nanoserver: Connecting to %s", addr);	
	if (strlen(addr) > NN_SOCKADDR_MAX) {
		return NULL;
	}
	
	if (strlen(name) >= NN_SERVER_MAX_NAME_SIZE) {
		return NULL;
	}

	socket_id = nn_socket(AF_SP, NN_PAIR);
	if (socket_id < 0) {
		return NULL;
	}
	
	if (nn_setsockopt(
				socket_id,
				NN_SOL_SOCKET,
				NN_SNDBUF,
				&set_bufsize,
				sizeof(set_bufsize)) != 0) {
		nn_log(LOG_ERR, "%s: Could not set nanomsg send buffer, %s", __func__, nn_strerror(errno));
		return NULL;
	}

	if (nn_setsockopt(
				socket_id,
				NN_SOL_SOCKET,
				NN_RCVBUF,
				&set_bufsize,
				sizeof(set_bufsize)) != 0) {
		nn_log(LOG_ERR, "%s: Could not set nanonsg recv buffer, %s", __func__, nn_strerror(errno));
		return NULL;
	}

	if (is_server == 0) {
		end_point = nn_connect(socket_id, addr);
		if (end_point < 0) {
			nn_log(LOG_ERR, "%s: Could not connect, %s", __func__, nn_strerror(errno));
			return NULL;
		}
	}

	else {
		end_point = nn_bind(socket_id, addr);
		if (end_point < 0) {
			return NULL;
		}
	}

	memset(nm_sock, 0, sizeof (*nm_sock));
	strncpy(nm_sock->uri,addr, NN_SOCKADDR_MAX);

	nm_sock->timestamp_sent_ka = 0;
	nm_sock->last_keepalive_recv = 0;
	nm_sock->keepalive_interval = KEEPALIVE_INTERVAL_SECONDS;
	nm_sock->keepalive_tolerance = KEEPALIVE_LOSE_TOLLERANCE;
	nm_sock->session_state = NM_SESSION_DOWN;
	nm_sock->socket_id = socket_id;
	nm_sock->is_server = is_server;
	nm_sock->on_msg_received = on_msg_received;
	nm_sock->on_disconnected = on_disconnected;
	nm_sock->on_established = on_established;
	nm_sock->check_should_yield = check_should_yield;
	nm_sock->session_id = rand();
	if (name){
		strncpy(nm_sock->name, name, NN_SERVER_MAX_NAME_SIZE);
	}
	nm_sock->args = args;
	pthread_spin_init(&nm_sock->send_lock, PTHREAD_PROCESS_PRIVATE);
	nm_sock->is_initiated = 1;
	return nm_sock;
}

void nm_transport_close(
		struct nm_transport_socket		*socket)
{
	if (!socket)
		return;

	if (!nm_transport_is_initiated (socket))
		return;

	nm_transport_change_channel_state (socket, NM_SESSION_DOWN);
	pthread_spin_destroy(&socket->send_lock);
	nn_close (socket->socket_id);
	memset(socket, 0, sizeof (*socket));
}


static int send_msg(
		struct nm_transport_socket	*socket, 
		NanoMsgEncapsulation		*msg_encap)
{
	uint8_t buf[NM_TRANSPORT_MAX_BUFFER_SIZE];
	unsigned buf_len;	
	int res;

	buf_len = nano_msg_encapsulation__get_packed_size(msg_encap);
	if (buf_len > NM_TRANSPORT_MAX_BUFFER_SIZE || buf_len == 0) {
		nn_log(LOG_ERR, "Send Failed, Msg too long or have zero size: %u", buf_len);
		return NANO_MSG_SEND_FAILED;
	}

	nano_msg_encapsulation__pack(msg_encap, buf);
	//@@@ hagai should this be blocking? res = nn_send(socket->socket_id, buf, buf_len, NN_DONTWAIT);
	res = nn_send(socket->socket_id, buf, buf_len, 0);
	if (res < 0) {
		if (EAGAIN == errno){
			return NANO_MSG_SEND_AGAIN;
		}
		nn_log(LOG_ERR, "%s: Could not send message, %s", __func__, nn_strerror(errno));
		return NANO_MSG_SEND_FAILED;
	}

	return res;	
}


static uint64_t get_time(void)
{
	return time(NULL);
}


static void handle_hello(struct nm_transport_socket *socket, NanoMsgEncapsulation *msg_encap, uint64_t timestamp)
{
	if (socket->session_state != NM_SESSION_DOWN) {
		if  (socket->session_id == msg_encap->session_id && socket->in_sequence_number == 0) {
			nn_log(LOG_WARNING, "Got multiple Hellos from %s", msg_encap->hello->name);
			return;
		}

		else {
			nn_log(LOG_ERR, "Got Hello from %s, with new session id: %i "
							 "but old session %i still running", 
			msg_encap->hello->name, msg_encap->session_id, socket->session_id);
		}
	}
	else {
		nn_log(LOG_DEBUG, "Got Hello from %s, session id: %i",
				msg_encap->hello->name, msg_encap->session_id);
	}

	memset(socket->pair_name, 0, sizeof(char)*NN_SERVER_MAX_NAME_SIZE);
	strncpy(socket->pair_name, msg_encap->hello->name, NN_SERVER_MAX_NAME_SIZE - 1);
	socket->in_sequence_number = 0;
	socket->out_sequence_number = 0;
	socket->session_id = msg_encap->session_id;
	if (msg_encap->hello->has_keepalive_interval){
		socket->keepalive_interval = msg_encap->hello->keepalive_interval;
		nn_log(LOG_DEBUG, ", keepalive_interval=%d"
				, socket->keepalive_interval);
	}

	if (msg_encap->hello->has_keepalive_tolerance){
		socket->keepalive_tolerance = msg_encap->hello->keepalive_tolerance;
		nn_log(LOG_DEBUG, ", keepalive_tolerance=%d"
				, socket->keepalive_tolerance);
	}

	nn_log(LOG_DEBUG,"\n");

	
	socket->last_keepalive_recv = timestamp;
	nm_transport_change_channel_state(socket, NM_SESSION_INIT);
	nanomsg_keepalive(socket, timestamp);
}


static void handle_keepalive(struct nm_transport_socket *socket, NanoMsgEncapsulation *msg_encap, uint64_t timestamp)
{
	if ((socket->session_state == NM_SESSION_INIT ||
	    socket->session_state == NM_SESSION_UP) &&
			(socket->session_id == msg_encap->session_id)) {
		/* You have brought shame upon our logs! SHAME!!! SHAME!!!  */
		/* nn_log(LOG_DEBUG, "Got Keepalive from %s, session id: %i ", */
		/* 		msg_encap->keepalive, msg_encap->session_id); */
		socket->last_keepalive_recv = timestamp;
		//Going to change state to up
		if (socket->session_state == NM_SESSION_INIT){
			nanomsg_keepalive(socket, timestamp);
		}
		nm_transport_change_channel_state(socket, NM_SESSION_UP);
	}
	else {
		nn_log(LOG_WARNING, "Got Keepalive from %s with session id: %i (Our session id: %i),"
				     "while session was not inited, being reseted or with wrong session id ",
				msg_encap->keepalive, msg_encap->session_id, socket->session_id);
	}
}


static void handle_data(struct nm_transport_socket *socket, NanoMsgEncapsulation *msg_encap, uint64_t timestamp)
{
	/* NO SOUP FOR YOU! */
	/* nn_log(LOG_DEBUG, "Got DATA msg, session: %i, index: %i", */
	/* 		msg_encap->session_id, */
	/* 		msg_encap->sequence_number); */

	if (NM_SESSION_UP == socket->session_state
			&& socket->session_id == msg_encap->session_id){
		if (msg_encap->sequence_number != ++socket->in_sequence_number) {
			nn_log(LOG_ERR, "Session %i out of sequence, "
					"got %i, expecting %i RESETING",
					socket->session_id,
					msg_encap->sequence_number,
					socket->in_sequence_number);
			nm_transport_change_channel_state(socket, NM_SESSION_RESETING);
			return;
		}

		if (socket->on_msg_received){
			socket->on_msg_received(
					msg_encap->data.data,
					msg_encap->data.len,
					socket->args);
		}
	socket->last_keepalive_recv = timestamp;

	}else{
		nn_log(LOG_DEBUG, "Ignoring DATA msg with session %i, msg seq num %i"
				", our Session %i our expected seq %i",
				msg_encap->session_id,
				msg_encap->sequence_number,
				socket->session_id,
				socket->in_sequence_number+1);
	}
}

static void handle_reset(struct nm_transport_socket *socket,  NanoMsgEncapsulation *msg_encap)
{
       nn_log(LOG_ERR, "Got RESET msg, session: %i",
                               msg_encap->session_id);
       nm_transport_change_channel_state(socket, NM_SESSION_RESETING);
}

static void nanomsg_hello(struct nm_transport_socket *socket, uint64_t timestamp)
{
	NanoMsgEncapsulation msg_encap = NANO_MSG_ENCAPSULATION__INIT;
	NanoMsgHello  msg_hello = NANO_MSG_HELLO__INIT;
	msg_encap.has_session_id = 1;
	msg_encap.session_id = socket->session_id;
	msg_encap.hello = &msg_hello;
	msg_encap.hello->name = (char *)(socket->name);
	msg_encap.hello->has_keepalive_interval = 1;
	msg_encap.hello->keepalive_interval = socket->keepalive_interval;
	msg_encap.hello->has_keepalive_tolerance = 1;
	msg_encap.hello->keepalive_tolerance = socket->keepalive_tolerance;

	msg_encap.nano_server_choice_case = NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_HELLO;

	nn_log(LOG_DEBUG, "Sending Hello session id %i, name %s",
		socket->session_id, msg_encap.hello->name);
	if (send_msg(socket, &msg_encap) > 0) {
		socket->in_sequence_number = 0;
		socket->out_sequence_number = 0;
		nm_transport_change_channel_state(socket, NM_SESSION_INIT);
	}	

	else {
		nn_log(LOG_WARNING, "Failed to send Hello");
	}

	socket->timestamp_sent_ka = timestamp;
	socket->last_keepalive_recv = timestamp;
}


static void nanomsg_keepalive(struct nm_transport_socket *socket, uint64_t timestamp)
{
	NanoMsgEncapsulation msg_encap = NANO_MSG_ENCAPSULATION__INIT;
	msg_encap.nano_server_choice_case = NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_KEEPALIVE;
	msg_encap.has_session_id = 1;
	msg_encap.session_id = socket->session_id;
	msg_encap.keepalive = socket->name;

	nn_log(LOG_DEBUG, "Sending Keepalive session %"PRIu32, socket->session_id);
	if (send_msg(socket, &msg_encap) < 0) {
		nn_log(LOG_WARNING, "Failed To send Keepalive");
	}

	socket->timestamp_sent_ka = timestamp;
}


int nanomsg_reset(struct nm_transport_socket *socket)
{
       if (socket->is_server == 0) {
               return 0;
       }

       nn_log(LOG_ERR, "Sending RESET to %s, for session %i",
               socket->pair_name, socket->session_id);
       NanoMsgEncapsulation msg_encap = NANO_MSG_ENCAPSULATION__INIT;
       msg_encap.nano_server_choice_case = NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_RESET;
       msg_encap.session_id = socket->session_id;
       msg_encap.has_session_id = 1;
       msg_encap.reset = 1;
       return send_msg(socket, &msg_encap);
}


int nm_transport_send_data(
		struct nm_transport_socket	*socket, 
		uint8_t						*msg, 
		int							len)
{
	int res;
	if (socket->session_state != NM_SESSION_UP) {
		nn_log(LOG_ERR, "Send Failed, Session is not open, cannot send msg");
		return NANO_MSG_SEND_FAILED;
	}

	pthread_spin_lock(&socket->send_lock);

	NanoMsgEncapsulation msg_encap = NANO_MSG_ENCAPSULATION__INIT;
	msg_encap.nano_server_choice_case = NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_DATA;
	msg_encap.data.len = len;
	msg_encap.data.data = msg;
	msg_encap.sequence_number = socket->out_sequence_number + 1;
	msg_encap.session_id = socket->session_id;
	msg_encap.has_session_id = 1;
	msg_encap.has_sequence_number = 1;
	res = send_msg(socket, &msg_encap);

	if (res >= 0)
	{
		socket->out_sequence_number += 1;
	}

	pthread_spin_unlock(&socket->send_lock);
	return res;
}

static int nm_should_yield(struct nm_transport_socket *socket, void *thread_context)
{

	if (socket->check_should_yield && thread_context){
		return socket->check_should_yield(thread_context);
	}else{
		return 0;
	}

}

static void nanomsg_recv_loop(struct nm_transport_socket *socket, uint64_t timestamp, void *thread_context)
{
	int i, len;
	uint8_t buf[NM_TRANSPORT_MAX_BUFFER_SIZE];

	NanoMsgEncapsulation *msg_encap;

	// To avoid client blocking other process the recv is limited to
	// MAX_RECEIVED_MSG_PER_LOOP in iteration. 
	for (i=0; i<MAX_RECEIVED_MSG_PER_LOOP; i++) {
		len = nn_recv(socket->socket_id, buf, NM_TRANSPORT_MAX_BUFFER_SIZE, NN_DONTWAIT); 

		// on error
		if (len < 0) {

			// Typically ETIMEDOUT indicates that no msg has been
			// recieved in the given time out so we ignore this
			if (EAGAIN != errno) {
				nn_log(LOG_ERR, "Got some errors on receive, we probably should fail: %s"
						,nn_strerror(errno));
			}

			break;
		} 
		
		msg_encap = nano_msg_encapsulation__unpack(NULL, len, buf);
		if (NULL == msg_encap) {
			nn_log(LOG_ERR, "Recv error: could not unpack msg");
			continue;
		}

		switch (msg_encap->nano_server_choice_case) {

		case NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_HELLO:
			handle_hello(socket, msg_encap, timestamp);
			break;

		case NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_KEEPALIVE:
			handle_keepalive(socket, msg_encap, timestamp);
			break;

		case NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_DATA:
			handle_data(socket, msg_encap, timestamp);
			break;

		case NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE_RESET:
			handle_reset(socket, msg_encap);
			break;

		case NANO_MSG_ENCAPSULATION__NANO_SERVER_CHOICE__NOT_SET:
		default:
			nn_log(LOG_ERR, "Recieved Illegal msg");
		}

		if (nm_should_yield(socket, thread_context)){
			nn_log(LOG_DEBUG, "nanomsg_recv_loop: loop exit because we should yield");
			break;
		}
	}
}

int nm_transport_client_loop(struct nm_transport_socket *socket, void *thread_context)
{
	uint64_t timestamp;
	uint64_t delta;
	int64_t signed_timestamp;
	signed_timestamp = get_time();
	if (signed_timestamp < 0) {
			nn_log(LOG_ERR, "failed to get linux time");
			return -1;
	}
	timestamp = (uint64_t)signed_timestamp;
	delta = timestamp - socket->timestamp_sent_ka;

	// sending hello when connection is up
	if (NM_SESSION_DOWN == socket->session_state && 
	    delta >= socket->keepalive_interval &&
	    socket->is_server == 0) {
		nanomsg_hello(socket, timestamp);
	}

	//seding keep alvies when session is inited or up
	if (NM_SESSION_DOWN != socket->session_state &&
	    delta >= socket->keepalive_interval) {
		nanomsg_keepalive(socket, timestamp);
	}

	// send recv loop
	nanomsg_recv_loop(socket, timestamp, thread_context);

	// handling keepalive lose
	if (socket->session_state != NM_SESSION_DOWN && 
	   timestamp - socket->last_keepalive_recv > 
			socket->keepalive_interval * socket->keepalive_tolerance) {
		nn_log(LOG_ERR, "Lost keepalive from session %i", socket->session_id);
		nm_transport_change_channel_state(socket, NM_SESSION_RESETING);
	}

	// sending fail to reset the session
	if (socket->session_state == NM_SESSION_RESETING) {
		nm_transport_change_channel_state(socket, NM_SESSION_DOWN);
		nanomsg_reset(socket);
	}

	if (socket->session_state == NM_SESSION_DOWN) {
		return -1;
	}

	// seccuess
	return 0;
}

int nm_transport_get_snd_event_socket(struct nm_transport_socket *trans_sock)
{
	int event_sock;
	int err;
	size_t sock_size = sizeof(event_sock);
	if (NM_SESSION_UNINITIALIZED == trans_sock->session_state){
		return -1;
	}

	err = nn_getsockopt(trans_sock->socket_id, NN_SOL_SOCKET, NN_SNDFD, &event_sock, &sock_size);

	if (err < 0){
		nn_log(LOG_ERR
				, "nm_transport_get_snd_event_socket: Could not get socket for send events: %s"
				, nn_strerror(errno));
		return -1;
	}

	return event_sock;
}

int nm_transport_get_rcv_event_socket(struct nm_transport_socket *trans_sock)
{
	int event_sock;
	int err;
	size_t sock_size = sizeof(event_sock);
	if (NM_SESSION_UNINITIALIZED == trans_sock->session_state){
		return -1;
	}

	err = nn_getsockopt(trans_sock->socket_id, NN_SOL_SOCKET, NN_RCVFD, &event_sock, &sock_size);

	if (err < 0){
		nn_log(LOG_ERR
				, "nm_transport_get_rcv_event_socket: Could not get socket for receive events: %s"
				, nn_strerror(errno));
		return -1;
	}

	return event_sock;
}

uint64_t nm_transport_get_seconds_till_ka(struct nm_transport_socket *trans_sock)
{
	uint64_t timestamp = get_time();
	uint64_t delta = timestamp - trans_sock->timestamp_sent_ka;

	nn_log(LOG_DEBUG
			, "nm_transport_get_seconds_till_ka: sock timestamp: %d, curr timestamp: %d, delta: %d"
			, trans_sock->timestamp_sent_ka
			, timestamp
			, delta);

	if (delta > trans_sock->keepalive_interval){
		return 0;
	}else {
		return trans_sock->keepalive_interval - delta;
	}

}

uint64_t nm_transport_get_seconds_ka_interval(struct nm_transport_socket *trans_sock)
{
	return trans_sock->keepalive_interval;
}


void nm_transport_stop_server(struct nm_transport_socket *socket)
{
       nn_close(socket->socket_id);
}

uint8_t nm_transport_is_initiated(struct nm_transport_socket *trans_sock)
{
	return trans_sock->is_initiated;
}

const char *
nm_transport_state_str (struct nm_transport_socket *s)
{
	if (!nm_transport_is_initiated(s))
		return "not initiated";

	switch (s->session_state)
	{
	case NM_SESSION_UNINITIALIZED:
		return "UNINITIALIZED";
	case NM_SESSION_DOWN:
		return "DOWN";
	case NM_SESSION_INIT:
		return "INIT";
	case NM_SESSION_UP:
		return "UP";
	case NM_SESSION_RESETING:
		return "RESETING";
	default:
		break;
	}

	return "unknown";
}

