
#ifndef NANOMSG_SERVICE_H_
#define NANOMSG_SERVICE_H_
#include <stdint.h>
#include <nanomsg/nn.h>
#include <syslog.h>

#define NN_SERVER_MAX_NAME_SIZE (32)


#define NANO_MSG_SEND_FAILED (-1)
#define NANO_MSG_SEND_AGAIN  (-2)
#define NANO_MSG_FAILED_SENDING_CTRL_MSG  (-3)



typedef void (*logger_callback)(int log_level, const char *msg, ...);
typedef void (*msg_received_callback)(uint8_t *msg, int len, void *args);
typedef void (*channel_state_changed_callback)(void *context);
typedef int (*should_yield_callback)(void *context);

enum session_state {
	NM_SESSION_UNINITIALIZED = 0,
	NM_SESSION_DOWN,
	NM_SESSION_INIT,
	NM_SESSION_UP,	
	NM_SESSION_RESETING,
};


// nano server data struct
struct nm_transport_socket {
	// session parameters
	char uri[NN_SOCKADDR_MAX + 1];
	char name[NN_SERVER_MAX_NAME_SIZE];
	char pair_name[NN_SERVER_MAX_NAME_SIZE];
	uint8_t is_initiated;

	int socket_id;
	uint64_t session_id;
	int is_server;
	enum session_state session_state;
	uint64_t out_sequence_number;
	uint64_t in_sequence_number;
	
	// keepalive paramters
	uint64_t keepalive_interval;
	uint32_t keepalive_tolerance; // number of keepalives me may skip
	uint64_t last_keepalive_recv;
	uint64_t timestamp_sent_ka;
	
	// callbacks
	msg_received_callback on_msg_received;
	channel_state_changed_callback on_established;
	channel_state_changed_callback on_disconnected;
	should_yield_callback check_should_yield;

	void *args;
}; 


/*
 * @brief init logger with a callback function
 * @param logger_callback_func function to be called with argument char *msg
 */
void nm_transport_init_logger(logger_callback logger_callback_func);

/*
 * @brief init nano msg server (usally cheetah side)
 * @param socket The socket we are initializing, it will be zeroed before usage.
 * @param addr 	The addr argument consists of two parts transport://address. 
 * 		 The transport specifies the underlying transport protocol to use. 
 * 		 The meaning of the address part is specific to the underlying transport protocol.  
 * @param timeout Timeout in seconds for not receiving keepalives
 * @param on_msg_received A callback for handling msg received on the run loop function
 * @params args Arguments to be called with on_msg_received callback
 * @return nm_scoket or NULL on error
 * sets errno with the error:
 * 	EAFNOSUPPORT: 	Specified address family is not supported.
 *	EINVAL: 	Unknown protocol.
 *	EMFILE: 	The limit on the total number of open SP sockets or 
 *			 OS limit for file descriptors has been reached.
 *	ETERM: 		The library is terminating.
 *	ENAMETOOLONG:	The supplied address is too long.
 *	EPROTONOSUPPORT:The requested transport protocol is not supported.
 *	ENODEV:		Address specifies a nonexistent interface.
 *	EBADF:		The provided socket is invalid.
 *
 */
struct nm_transport_socket *nm_transport_init(struct nm_transport_socket *socket,
	const char *addr, 
	const char *name, 
	int is_server,
	msg_received_callback on_msg_received,
	channel_state_changed_callback on_established,
	channel_state_changed_callback on_disconnected,
	should_yield_callback			check_should_yield,
	void *args);

/*
 * @brief Close a nano msg socket
 * @param socket The socket we are closing, it will be zeroed after close.
 * */
void nm_transport_close(
		struct nm_transport_socket		*socket);


/*
 * @brief Sending a blocking msg
 * @params socket Socket got from the init function
 * @params msg A string based msg to be send
 * @params len Msg len
 * @return Return the length of the send item (>0) or error (-1) or send again code (-2)
 */
int nm_transport_send_data(struct nm_transport_socket *socket, uint8_t *msg, int len);

/*
 * @brief Main client loop, incharge of health checks and recv msgs
 * @params socket_id Socket id got from the init function
 * @params thread_context thread context for checking if we need to yield
 * @return 0 on Success -1 on server reset
 */
int nm_transport_client_loop(struct nm_transport_socket *socket, void *thread_context);

///*
// * @brief Get the status of the channel.
// * @params socket
// * @return session state (UP/DOWN/INIT...)
// */
//enum session_state nm_transport_get_channel_status(struct nm_transport_socket *socket);

/*
 * @brief Get socket from nn for read events.
 * @params nm_transport_socket
 * @return posix socket
 */
int nm_transport_get_rcv_event_socket(struct nm_transport_socket *socket);

/*
 * @brief Get socket from nn for write events.
 * @params nm_transport_socket
 * @return posix socket
 */
int nm_transport_get_snd_event_socket(struct nm_transport_socket *socket);


/*
 * @brief Get time till next ka/hello message to be sent.
 * @params nm_transport_socket
 * @return seconds
 */
uint64_t nm_transport_get_seconds_till_ka(struct nm_transport_socket *trans_sock);


/*
 * @brief Get ka/hello messages interval in seconds.
 * @params nm_transport_socket
 * @return seconds
 */
uint64_t nm_transport_get_seconds_ka_interval(struct nm_transport_socket *trans_sock);


/*
 * @brief Returns 1 if it was initiated, 0 otherwise
 * @params nm_transport_socket
 * @return {0,1}
 */
uint8_t nm_transport_is_initiated(struct nm_transport_socket *trans_sock);


/*
 * @brief Closes the nn_socket.
 * @params nm_transport_socket
 * @return seconds
 */
void nm_transport_stop_server(struct nm_transport_socket *socket);

/*
 * @brief Print session state
 * @params nm_transport_socket
 * @return String representation of the session state
 */
const char *nm_transport_state_str (struct nm_transport_socket *s);


#endif // NANOMSG_SERVICE_H_
