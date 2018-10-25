/*
    Originally copied from https://github.com/zeromq/rbzmq/blob/master/rbzmq.c
    Including their copyright notification.
*/
/*
    Copyright (c) 2007-2010 iMatix Corporation

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the Lesser GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Lesser GNU General Public License for more details.

    You should have received a copy of the Lesser GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <string.h>
#include <ruby.h>
#include <ruby/io.h>
#include <ruby/thread.h>
#include <zmq.h>
#include <stdint.h>

struct zmq_context {
    void *context;
    unsigned refs;
};

struct zmq_socket {
    void *socket;
    struct zmq_context *context;
    // Is this socket a monitor?  If C had booleans, this would be one
    int monitor;
};

struct zmq_poller {
  int nitems;
  zmq_pollitem_t *items;
  VALUE *sockets;
};

#define Check_Socket(__socket) \
    do {\
        if ((__socket->socket) == NULL)\
            rb_raise (rb_eIOError, "closed socket");\
    } while(0)

VALUE socket_type;
VALUE exception_type;

/*
 * Document-class: ZMQ
 *
 * Ruby interface to the zeromq messaging library.
 */

/*
 * call-seq:
 *   ZMQ.version() -> [major, minor, patch]
 *
 * Returns the version of the zeromq library.
 */
static VALUE module_version (VALUE self_)
{
    int major, minor, patch;

    zmq_version(&major, &minor, &patch);

    return rb_ary_new3 (3, INT2NUM (major), INT2NUM (minor), INT2NUM (patch));
}

/*
 * call-seq:
 *   ZMQ::Util.curve_keypair() -> []
 *
 * Return a newly generated random keypair consisting of a public key and a secret key
 */
static VALUE util_curve_keypair (VALUE self_)
{
  char z85_public_key[41];
  char z85_secret_key[41];
  int rc = zmq_curve_keypair(z85_public_key, z85_secret_key);

  if (rc == -1) {
    rb_raise(exception_type, "%s", zmq_strerror (zmq_errno ()));
    return Qnil;
  }

  VALUE pk = rb_str_new_cstr(z85_public_key);
  VALUE sk = rb_str_new_cstr(z85_secret_key);
  return rb_ary_new_from_args(2, pk, sk);

}

/*
 * Document-class: ZMQ::Context
 *
 * ZeroMQ library context.
 */
static void context_free (void *ptr)
{
    struct zmq_context * ctx = (struct zmq_context *)ptr;

    assert(ctx->refs != 0);
    ctx->refs--;

    if (ctx->refs == 0) {
        if (ctx->context != NULL) {
            int rc = zmq_ctx_destroy(ctx->context);
            assert (rc == 0);
        }

        xfree(ctx);
    }
}

static VALUE context_alloc (VALUE class_)
{
    struct zmq_context * ctx;

    ctx = ALLOC(struct zmq_context);
    ctx->context = NULL;
    ctx->refs = 1;

    return rb_data_object_alloc (class_, ctx, 0, context_free);
}

/*
 * Document-method: new
 *
 * call-seq:
 *   new(io_threads=1)
 *
 * Initializes a new 0MQ context. The io_threads argument specifies the size
 * of the 0MQ thread pool to handle I/O operations. If your application is
 * using only the _inproc_ transport for you may set this to zero; otherwise,
 * set it to at least one.
 */

static VALUE context_initialize (int argc_, VALUE* argv_, VALUE self_)
{
    VALUE io_threads;
    rb_scan_args (argc_, argv_, "01", &io_threads);

    struct zmq_context * ctx = NULL;
    Data_Get_Struct (self_, void, ctx);

    assert (ctx->context == NULL);
    void *zctx = zmq_ctx_new();
    if (!zctx) {
        rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
        return Qnil;
    }

    ctx->context = zctx;
    return self_;
}

static void poller_free (void *ptr)
{
    struct zmq_poller * poller = (struct zmq_poller *)ptr;

    xfree(poller->items);
    xfree(poller->sockets);
    xfree(poller);
}

static VALUE poller_alloc (VALUE class_)
{
    struct zmq_poller * poller;

    poller = ALLOC(struct zmq_poller);
    poller->nitems = 0;
    // We can get away without resizing this because we know in Push Jobs
    // there are only 2 sockets to track
    poller->items = ALLOC_N(zmq_pollitem_t, 2);
    poller->sockets = ALLOC_N(VALUE, 2);

    return rb_data_object_alloc (class_, poller, 0, poller_free);
}

/*
 * Document-method: new
 *
 * call-seq:
 *   new()
 *
 * Initializes a poller with an empty list of poll items.
 */
static VALUE poller_initialize (VALUE self_)
{
    struct zmq_poller * poller = NULL;
    Data_Get_Struct (self_, struct zmq_poller, poller);

    // TODO need anything else in here? Or did it all in alloc?

    return self_;
}

static void socket_free (void *ptr)
{
    struct zmq_socket *s = (struct zmq_socket *)ptr;

    if (s->socket != NULL) {
        int rc = zmq_close(s->socket);
        assert (rc == 0);
    }

    if (s->context != NULL) {
        /* Decrement the refcounter for the context (and possibly free it). */
        context_free(s->context);
    }

    xfree(s);
}

/*
 * Document-method: socket
 *
 * call-seq:
 *   zmq.socket(socket_type)
 *
 * Creates a new 0MQ socket.  The socket_type argument specifies the socket
 * type, which determines the semantics of communication over the socket.
 *
 * The newly created socket is initially unbound, and not associated with any
 * endpoints. In order to establish a message flow a socket must first be
 * connected to at least one endpoint with connect(), or at least one
 * endpoint must be created for accepting incoming connections with
 * bind().
 *
 * For a description of the various socket types, see ZMQ::Socket.
 */
static VALUE context_socket (VALUE self_, VALUE type_)
{
    struct zmq_context * ctx = NULL;
    void *socket;
    struct zmq_socket *s;

    Data_Get_Struct (self_, void, ctx);

    socket = zmq_socket(ctx->context, NUM2INT (type_));
    if (!socket) {
        rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
        return Qnil;
    }

    s = ALLOC(struct zmq_socket);

    /*
     * Grab a reference on the context, to prevent it from being garbage-
     * collected before the socket is closed.
     */
    s->context = ctx;
    s->context->refs++;
    // normal socket here:
    s->monitor = 0;

    s->socket = socket;

    return Data_Wrap_Struct(socket_type, 0, socket_free, s);
}

/*
 * call-seq:
 *   socket.setsockopt(option, value) -> nil
 *
 * Sets the value of a 0MQ socket option.
 *
 * The following socket options can be set with the setsockopt() function:
 *
 * == ZMQ::SNDHWM: Set send high water mark
 * The ZMQ::SNDHWM option shall set the high water mark for the specified _socket_.
 * The high water mark is a hard limit on the maximum number of outstanding
 * messages 0MQ shall queue in memory for any single peer that the specified
 * _socket_ is communicating with.
 *
 * If this limit has been reached the socket shall enter an exceptional state
 * and depending on the socket type, 0MQ shall take appropriate action such as
 * blocking or dropping sent messages. Refer to the individual socket
 * descriptions in ZMQ::Socket for details on the exact action taken for each
 * socket type.
 *
 * The default ZMQ::SNDHWM value of zero means "no limit".
 *
 * [Option value type] Integer
 * [Option value unit] messages
 * [Default value] 0
 * [Applicable socket types] all
 *
 * == ZMQ::RCVHWM: Set receive high water mark
 * The ZMQ::RCVHWM option shall set the high water mark for the specified _socket_.
 * The high water mark is a hard limit on the maximum number of outstanding
 * messages 0MQ shall queue in memory for any single peer that the specified
 * _socket_ is communicating with.
 *
 * If this limit has been reached the socket shall enter an exceptional state
 * and depending on the socket type, 0MQ shall take appropriate action such as
 * blocking or dropping received messages. Refer to the individual socket
 * descriptions in ZMQ::Socket for details on the exact action taken for each
 * socket type.
 *
 * The default ZMQ::RCVHWM value of zero means "no limit".
 *
 * [Option value type] Integer
 * [Option value unit] messages
 * [Default value] 0
 * [Applicable socket types] all
 *
 * == ZMQ::HWM: Set high water mark (0MQ 2.x only)
 * The ZMQ::HWM option shall set the high water mark for the specified _socket_.
 * The high water mark is a hard limit on the maximum number of outstanding
 * messages 0MQ shall queue in memory for any single peer that the specified
 * _socket_ is communicating with.
 *
 * If this limit has been reached the socket shall enter an exceptional state
 * and depending on the socket type, 0MQ shall take appropriate action such as
 * blocking or dropping sent messages. Refer to the individual socket
 * descriptions in ZMQ::Socket for details on the exact action taken for each
 * socket type.
 *
 * The default ZMQ::HWM value of zero means "no limit".
 *
 * [Option value type] Integer
 * [Option value unit] messages
 * [Default value] 0
 * [Applicable socket types] all
 *
 * == ZMQ::SWAP: Set disk offload size (0MQ 2.x only)
 * The ZMQ::SWAP option shall set the disk offload (swap) size for the specified
 * socket. A socket which has ZMQ::SWAP set to a non-zero value may exceed it’s
 * high water mark; in this case outstanding messages shall be offloaded to
 * storage on disk rather than held in memory.
 *
 * The value of ZMQ::SWAP defines the maximum size of the swap space in bytes.
 *
 * [Option value type] Integer
 * [Option value unit] bytes
 * [Default value] 0
 * [Applicable socket types] all
 *
 * == ZMQ::AFFINITY: Set I/O thread affinity
 * The ZMQ::AFFINITY option shall set the I/O thread affinity for newly created
 * connections on the specified socket.
 *
 * Affinity determines which threads from the 0MQ I/O thread pool associated
 * with the socket’s _context_ shall handle newly created connections. A value of
 * zero specifies no affinity, meaning that work shall be distributed fairly
 * among all 0MQ I/O threads in the thread pool. For non-zero values, the lowest
 * bit corresponds to thread 1, second lowest bit to thread 2 and so on. For
 * example, a value of 3 specifies that subsequent connections on socket shall
 * be handled exclusively by I/O threads 1 and 2.
 *
 * See also ZMQ::Context#new for details on allocating the number of I/O threads
 * for a specific _context_.
 *
 * [Option value type] Integer
 * [Option value unit] N/A (bitmap)
 * [Default value] 0
 * [Applicable socket types] all
 *
 * == ZMQ::IDENTITY: Set socket identity
 * The ZMQ::IDENTITY option shall set the identity of the specified socket.
 * Socket identity determines if existing 0MQ infastructure (<em>message queues</em>,
 * <em>forwarding devices</em>) shall be identified with a specific application and
 * persist across multiple runs of the application.
 *
 * If the socket has no identity, each run of an application is completely
 * separate from other runs. However, with identity set the socket shall re-use
 * any existing 0MQ infrastructure configured by the previous run(s). Thus the
 * application may receive messages that were sent in the meantime, <em>message
 * queue</em> limits shall be shared with previous run(s) and so on.
 *
 * Identity should be at least one byte and at most 255 bytes long. Identities
 * starting with binary zero are reserved for use by 0MQ infrastructure.
 *
 * [Option value type] String
 * [Option value unit] N/A
 * [Default value] nil
 * [Applicable socket types] all
 *
 * == ZMQ::SUBSCRIBE: Establish message filter
 * The ZMQ::SUBSCRIBE option shall establish a new message filter on a ZMQ::SUB
 * socket. Newly created ZMQ::SUB sockets shall filter out all incoming messages,
 * therefore you should call this option to establish an initial message filter.
 *
 * An empty _value_ of length zero shall subscribe to all incoming messages. A
 * non-empty _value_ shall subscribe to all messages beginning with the
 * specified prefix. Mutiple filters may be attached to a single ZMQ::SUB socket,
 * in which case a message shall be accepted if it matches at least one filter.
 *
 * [Option value type] String
 * [Option value unit] N/A
 * [Default value] N/A
 * [Applicable socket types] ZMQ::SUB
 *
 * == ZMQ::UNSUBSCRIBE: Remove message filter
 * The ZMQ::UNSUBSCRIBE option shall remove an existing message filter on a
 * ZMQ::SUB socket. The filter specified must match an existing filter
 * previously established with the ZMQ::SUBSCRIBE option. If the socket has
 * several instances of the same filter attached the ZMQ::UNSUBSCRIBE option
 * shall remove only one instance, leaving the rest in place and functional.
 *
 * [Option value type] String
 * [Option value unit] N/A
 * [Default value] nil
 * [Applicable socket types] all
 *
 * == ZMQ::RATE: Set multicast data rate
 * The ZMQ::RATE option shall set the maximum send or receive data rate for
 * multicast transports such as _pgm_ using the specified socket.
 *
 * [Option value type] Integer
 * [Option value unit] kilobits per second
 * [Default value] 100
 * [Applicable socket types] all, when using multicast transports
 *
 * == ZMQ::RECOVERY_IVL: Set multicast recovery interval
 * The ZMQ::RECOVERY_IVL option shall set the recovery interval for multicast
 * transports using the specified _socket_. The recovery interval determines the
 * maximum time in seconds that a receiver can be absent from a multicast group
 * before unrecoverable data loss will occur.
 *
 * <bCaution:</b> Exercise care when setting large recovery intervals as the data
 * needed for recovery will be held in memory. For example, a 1 minute recovery
 * interval at a data rate of 1Gbps requires a 7GB in-memory buffer.
 *
 * [Option value type] Number
 * [Option value unit] seconds
 * [Default value] 10
 * [Applicable socket types] all, when using multicast transports
 *
 * == ZMQ::MCAST_LOOP: Control multicast loopback (0MQ 2.x only)
 * The ZMQ::MCAST_LOOP option shall control whether data sent via multicast
 * transports using the specified _socket_ can also be received by the sending
 * host via loopback. A value of zero disables the loopback functionality, while
 * the default value of 1 enables the loopback functionality. Leaving multicast
 * loopback enabled when it is not required can have a negative impact on
 * performance. Where possible, disable ZMQ::MCAST_LOOP in production
 * environments.
 *
 * [Option value type] Boolean
 * [Option value unit] N/A
 * [Default value] true
 * [Applicable socket types] all, when using multicast transports
 *
 * == ZMQ::SNDBUF: Set kernel transmit buffer size
 * The ZMQ::SNDBUF option shall set the underlying kernel transmit buffer size
 * for the socket to the specified size in bytes. A value of zero means leave
 * the OS default unchanged. For details please refer to your operating system
 * documentation for the SO_SNDBUF socket option.
 *
 * [Option value type] Integer
 * [Option value unit] bytes
 * [Default value] 0
 * [Applicable socket types] all
 *
 * == ZMQ::RCVBUF: Set kernel receive buffer size
 * The ZMQ::RCVBUF option shall set the underlying kernel receive buffer size
 * for the socket to the specified size in bytes. A value of zero means leave
 * the OS default unchanged. For details refer to your operating system
 * documentation for the SO_RCVBUF socket option.
 *
 * [Option value type] Integer
 * [Option value unit] bytes
 * [Default value] 0
 * [Applicable socket types] all
 *
 * == ZMQ::LINGER: Set linger period for socket shutdown
 * The ZMQ::LINGER option shall set the linger period for the specified
 * socket. The linger period determines how long pending messages which have
 * yet to be sent to a peer shall linger in memory after a socket is closed
 * with ZMQ::Socket#close(), and further affects the termination of the
 * socket’s context with ZMQ#close(). The following outlines the different
 * behaviours:
 *
 * * The default value of −1 specifies an infinite linger period.
 *   Pending messages shall not be discarded after a call to ZMQ::Socket#close();
 *   attempting to terminate the socket’s context with ZMQ::Context#close() shall block
 *   until all pending messages have been sent to a peer.
 *
 * * The value of 0 specifies no linger period. Pending messages shall be
 *   discarded immediately when the socket is closed with ZMQ::Socket#close.
 *
 * * Positive values specify an upper bound for the linger period in
 *   milliseconds. Pending messages shall not be discarded after a call to
 *   ZMQ::Socket#close(); attempting to terminate the socket’s context with
 *   ZMQ::Context#close() shall block until either all pending messages have been sent
 *   to a peer, or the linger period expires, after which any pending messages
 *   shall be discarded.
 *
 * [Option value type] Integer
 * [Option value unit] milliseconds
 * [Default value] -1 (infinite)
 * [Applicable socket types] all
 *
 * == ZMQ::RECONNECT_IVL: Set reconnection interval
 * The ZMQ::RECONNECT_IVL option shall set the reconnection interval for
 * the specified socket. The reconnection interval is the maximum period 0MQ
 * shall wait between attempts to reconnect disconnected peers when using
 * connection−oriented transports.
 *
 * [Option value type] Integer
 * [Option value unit] milliseconds
 * [Default value] 100
 * [Applicable socket types] all, only for connection-oriented transports
 *
 * == ZMQ::BACKLOG: Set maximum length of the queue of outstanding connections
 * The ZMQ::BACKLOG option shall set the maximum length of the queue of
 * outstanding peer connections for the specified socket; this only applies to
 * connection−oriented transports. For details refer to your operating system
 * documentation for the listen function.
 *
 * [Option value type] Integer
 * [Option value unit] connections
 * [Default value] 100
 * [Applicable socket types] all, only for connection-oriented transports
 *
 * == ZMQ::SNDTIMEO
 * Sets the timeout for send operations on the socket.
 *
 * If the value is 0, a send operation on the socket will return immediately, with a
 * EAGAIN error if the message cannot be sent. If the value is -1, it will block until the
 * message is sent. For all other values, it will try to send the message for that amount
 * of time before returning with an EAGAIN error.
 *
 * [Option value type] Integer
 * [Option value unit] milliseconds
 * [Default value] -1 (infinite)
 * [Applicable socket types] all
 *
 * == ZMQ::RCVTIMEO
 * Sets the timeout for receive operations on the socket.
 *
 * If the value is 0, a receive operation on the socket will return immediately, with a
 * EAGAIN error if there is no message to receive. If the value is -1, it will block until
 * a message is available. For all other values, it will wait for a message for that
 * amount of time before returning with an EAGAIN error.
 *
 * [Option value type] Integer
 * [Option value unit] milliseconds
 * [Default value] -1 (infinite)
 * [Applicable socket types] all
 *
 */
static VALUE socket_setsockopt (VALUE self_, VALUE option_, VALUE optval_)
{

    int rc = 0;
    struct zmq_socket * s;

    Data_Get_Struct (self_, struct zmq_socket, s);
    Check_Socket (s);

    switch (NUM2INT (option_)) {

    case ZMQ_LINGER:
    case ZMQ_SNDHWM:
    case ZMQ_RCVHWM:
        {
            int opt = FIX2INT(option_);
            int optval = NUM2INT(optval_);

            //  Forward the code to native 0MQ library.
            rc = zmq_setsockopt (s->socket, opt,
                (void*) &optval, sizeof (optval));
        }
        break;

    case ZMQ_SUBSCRIBE:
    case ZMQ_CURVE_SERVERKEY:
    case ZMQ_CURVE_PUBLICKEY:
    case ZMQ_CURVE_SECRETKEY:

        //  Forward the code to native 0MQ library.
        rc = zmq_setsockopt (s->socket, NUM2INT (option_),
	    (void *) StringValueCStr (optval_), RSTRING_LEN (optval_));
        break;

    default:
        rb_raise (exception_type, "%s", zmq_strerror (EINVAL));
        return Qnil;
    }

    if (rc != 0) {
        rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
        return Qnil;
    }

    return self_;
}

/*
 * call-seq:
 *   socket.connect(endpoint) -> nil
 *
 * Connects the socket to the endpoint specified by the _endpoint_ argument.
 *
 * The _endpoint_ argument is a string consisting of two parts as follows:
 * _transport://address_.  The _transport_ part specifies the underlying
 * transport protocol to use.  The meaning of the _address_ part is specific
 * to the underlying transport protocol selected.
 *
 * The following transports are defined:
 *
 * [_inproc_] local in-process (inter-thread) communication transport
 * [_ipc_] local inter-process communication transport
 * [_tcp_] unicast transport using TCP
 * [_pgm_, _epgm_] reliable multicast transport using PGM
 *
 * With the exception of ZMQ:PAIR sockets, a single socket may be connected to
 * multiple endpoints using connect(), while simultaneously accepting
 * incoming connections from multiple endpoints bound to the socket using
 * bind(). Refer to ZMQ::Socket for a description of the exact semantics
 * involved when connecting or binding a socket to multiple endpoints.
 *
 * <b>NOTE:</b> The connection will not be performed immediately, but as needed by
 * 0MQ.  Thus, a successful invocation of connect() does not indicate that
 * a physical connection was or can actually be established.
 */
static VALUE socket_connect (VALUE self_, VALUE addr_)
{
    struct zmq_socket * s;
    Data_Get_Struct (self_, struct zmq_socket, s);
    Check_Socket (s);

    int rc = zmq_connect (s->socket, rb_string_value_cstr (&addr_));
    if (rc != 0) {
        rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
        return Qnil;
    }

    return Qnil;
}

struct zmq_send_recv_args {
    void *socket;
    zmq_msg_t *msg;
    int flags;
    int rc;
};

static void * zmq_send_blocking (void* args_)
{
    struct zmq_send_recv_args *send_args = (struct zmq_send_recv_args *)args_;

    send_args->rc = zmq_msg_send(send_args->msg, send_args->socket, send_args->flags);

    return NULL;
}

/*
 * call-seq:
 *   socket.send(message, flags=0) -> true | false
 *
 * Queue the message referenced by the _msg_ argument to be send to the
 * _socket_.  The _flags_ argument is a combination of the flags defined
 * below:
 *
 * [ZMQ::DONTWAIT] Specifies that the operation should be performed in
 * non-blocking mode. If the message cannot be queued on the _socket_,
 * the function shall fail and return _false_.
 * [ZMQ::SNDMORE] Specifies that the message being sent is a multi-part message,
 * and that further message parts are to follow. Refer to the section regarding
 * multi-part messages below for a detailed description.
 *
 * <b>NOTE:</b> A successful invocation of send() does not indicate that the
 * message has been transmitted to the network, only that it has been queued on
 * the socket and 0MQ has assumed responsibility for the message.
 *
 * == Multi-part messages
 * A 0MQ message is composed of 1 or more message parts. 0MQ ensures atomic
 * delivery of messages; peers shall receive either all <em>message parts</em> of a
 * message or none at all.
 *
 * The total number of message parts is unlimited.
 *
 * An application wishing to send a multi-part message does so by specifying the
 * ZMQ::SNDMORE flag to send(). The presence of this flag indicates to 0MQ
 * that the message being sent is a multi-part message and that more message
 * parts are to follow. When the application wishes to send the final message
 * part it does so by calling send() without the ZMQ::SNDMORE flag; this
 * indicates that no more message parts are to follow.
 *
 * This function returns _true_ if successful, _false_ if not.
 */
static VALUE socket_send (int argc_, VALUE* argv_, VALUE self_)
{
    VALUE msg_, flags_;

    rb_scan_args (argc_, argv_, "11", &msg_, &flags_);

    struct zmq_socket * s;
    Data_Get_Struct (self_, struct zmq_socket, s);
    Check_Socket (s);

    Check_Type (msg_, T_STRING);

    int flags = NIL_P (flags_) ? 0 : NUM2INT (flags_);

    zmq_msg_t msg;
    int msg_len = (int)RSTRING_LEN (msg_);
    int rc = zmq_msg_init_size (&msg, msg_len);
    if (rc != 0) {
        rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
        return Qnil;
    }
    memcpy (zmq_msg_data (&msg), RSTRING_PTR (msg_), msg_len);

    if (!(flags & ZMQ_DONTWAIT)) {
        struct zmq_send_recv_args send_args;
        send_args.socket = s->socket;
        send_args.msg = &msg;
        send_args.flags = flags;
        rb_thread_call_without_gvl (zmq_send_blocking, (void*) &send_args, NULL, NULL);
        rc = send_args.rc;
    }
    else
        rc = zmq_msg_send (&msg, s->socket, flags);

    if (rc == -1 && zmq_errno () == EAGAIN) {
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qfalse;
    }

    if (rc == -1) {
        rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qnil;
    }

    rc = zmq_msg_close (&msg);
    assert (rc == 0);
    return Qtrue;
}

static void * zmq_recv_blocking (void* args_)
{
    struct zmq_send_recv_args *recv_args = (struct zmq_send_recv_args *)args_;

    recv_args->rc = zmq_msg_recv(recv_args->msg, recv_args->socket, recv_args->flags);

    return NULL;
}

/*
 * call-seq:
 *   socket.recv(flags=0) -> message | nil
 *
 * Receives a message from the _socket_.  If there are no messages available
 * on the _socket_, the recv() function shall block until the request can be
 * satisfied.  The _flags_ argument is a combination of the flags defined
 * below:
 *
 * [ZMQ::DONTWAIT] Specifies that the operation should be performed in
 * non-blocking mode.  If there are no messages available on the _socket_,
 * the recv() function shall fail and return _nil_.
 *
 * == Multi-part messages
 * A 0MQ message is composed of 1 or more message parts. 0MQ ensures atomic
 * delivery of messages; peers shall receive either all <em>message parts</em> of a
 * message or none at all.
 *
 * The total number of message parts is unlimited.
 *
 * An application wishing to determine if a message is composed of multiple
 * parts does so by retrieving the value of the ZMQ::RCVMORE socket option on the
 * socket it is receiving the message from, using getsockopt(). If there are no
 * message parts to follow, or if the message is not composed of multiple parts,
 * ZMQ::RCVMORE shall report a value of false. Otherwise, ZMQ::RCVMORE shall
 * report a value of true, indicating that more message parts are to follow.
 */
static VALUE socket_recv (int argc_, VALUE* argv_, VALUE self_)
{
    VALUE flags_;

    rb_scan_args (argc_, argv_, "01", &flags_);

    struct zmq_socket * s;
    Data_Get_Struct (self_, struct zmq_socket, s);
    Check_Socket (s);

    int flags = NIL_P (flags_) ? 0 : NUM2INT (flags_);

    zmq_msg_t msg;
    int rc = zmq_msg_init (&msg);
    assert (rc == 0);

    if (!(flags & ZMQ_DONTWAIT)) {
        struct zmq_send_recv_args recv_args;
        recv_args.socket = s->socket;
        recv_args.msg = &msg;
        recv_args.flags = flags;
        rb_thread_call_without_gvl (zmq_recv_blocking, (void*) &recv_args,
            NULL, NULL);
        rc = recv_args.rc;
    }
    else
        rc = zmq_msg_recv (&msg, s->socket, flags);
    if (rc == -1 && zmq_errno () == EAGAIN) {
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qnil;
    }

    if (rc == -1) {
        rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
        rc = zmq_msg_close (&msg);
        assert (rc == 0);
        return Qnil;
    }

    VALUE message = rb_str_new ((char*) zmq_msg_data (&msg), zmq_msg_size (&msg));
    rc = zmq_msg_close (&msg);
    assert (rc == 0);
    return message;
}

/*
 * call-seq:
 *   socket.close() -> nil
 *
 * Destroys the 0MQ socket.  Any outstanding messages physically received from
 * the network but not yet received by the application with ZMQ::Socket#recv()
 * shall be discarded. The behaviour for discarding messages sent by the
 * application with ZMQ::Socket#send() but not yet physically transferred to
 * the network depends on the value of the ZMQ::LINGER socket option for the
 * socket.
 */
static VALUE socket_close (VALUE self_)
{
    struct zmq_socket * s;
    Data_Get_Struct (self_, struct zmq_socket, s);
    if (s->socket != NULL) {
        int rc = zmq_close(s->socket);
        if (rc != 0) {
            rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
            return Qnil;
        }

        s->socket = NULL;

        /* Decrement the refcounter for the context (and possibly free it). */
        context_free(s->context);
        s->context = NULL;
    }
    return Qnil;
}

/*
 * call-seq:
 *   socket.more_parts?() -> true | false
 */
static VALUE socket_more_parts (VALUE self_)
{
  VALUE retval;
  struct zmq_socket * s;
  Data_Get_Struct (self_, struct zmq_socket, s);
  Check_Socket (s);

  int opt = ZMQ_RCVMORE;
  int optval;
  size_t optvalsize = sizeof(optval);

  int rc = zmq_getsockopt (s->socket, opt, (void *)&optval, &optvalsize);

  if (rc != 0) {
    rb_raise (exception_type, "%s", zmq_strerror (zmq_errno ()));
    return Qnil;
  }

  retval = optval ? Qtrue : Qfalse;

  return retval;
}

/*
 * call-seq:
 *   poller.register_readable(socket)
 */
static VALUE poller_register_readable (VALUE self_, VALUE socket_)
{
    struct zmq_socket * s;
    Data_Get_Struct (socket_, struct zmq_socket, s);
    Check_Socket (s);

    struct zmq_poller * poller;
    Data_Get_Struct (self_, struct zmq_poller, poller);

    // convert socket into zmq_politem_t
    zmq_pollitem_t *item = &poller->items[poller->nitems];

    item->socket = s->socket;
    item->fd = -1;
    item->events = ZMQ_POLLIN;

    poller->sockets[poller->nitems] = socket_;

    poller->nitems++;

    return Qnil;
}

/*
 * call-seq:
 *   poller.poll(timeout)
 *
 * timeout should be provided in milliseconds
 */
static VALUE poller_poll (VALUE self_, VALUE timeout_)
{
    struct zmq_poller * poller;
    Data_Get_Struct (self_, struct zmq_poller, poller);

    long timeout = (long)(NUM2DBL (timeout_));
    int rc;

    rc = zmq_poll (poller->items, poller->nitems, timeout);

    if (rc == -1) {
        rb_raise(exception_type, "%s", zmq_strerror (zmq_errno ()));
    }

    return Qnil;
}

/*
 * call-seq:
 *   poller.readables -> [sockets]
 *
 * Returns any sockets that had ZMQ_POLLIN set on them after .poll was called
 */
 static VALUE poller_readables (VALUE self_)
 {
     struct zmq_poller * poller;
     Data_Get_Struct (self_, struct zmq_poller, poller);

     VALUE readables = rb_ary_new();

     for (int i=0; i < poller->nitems; i++) {
       zmq_pollitem_t *item = &poller->items[i];
       if (item->revents & ZMQ_POLLIN) {
         VALUE s = poller->sockets[i];
         rb_ary_push(readables, s);
       }
     }

     return readables;
 }

void Init_zmq ()
{
    // This exists to mimic how ffi-rzmq's `LibZMQ.version` is used
    // reference: https://github.com/chuckremes/ffi-rzmq-core/blob/1.0.5/lib/ffi-rzmq-core/utilities.rb#L11-L21
    VALUE libzmq_module = rb_define_module ("LibZMQ");
    rb_define_singleton_method (libzmq_module, "version", module_version, 0);

    VALUE zmq_module = rb_define_module ("ZMQ");
    rb_define_singleton_method (zmq_module, "version", module_version, 0);

    exception_type = rb_define_class_under (zmq_module, "Error", rb_eRuntimeError );

    VALUE util_type = rb_define_class_under (zmq_module, "Util", rb_cObject);
    rb_define_singleton_method (util_type, "curve_keypair", util_curve_keypair, 0);

    VALUE context_type = rb_define_class_under (zmq_module, "Context",
        rb_cObject);
    rb_define_alloc_func (context_type, context_alloc);
    rb_define_method (context_type, "initialize", context_initialize, -1);
    rb_define_method (context_type, "socket", context_socket, 1);

    socket_type = rb_define_class_under (zmq_module, "Socket", rb_cObject);
    rb_undef_alloc_func(socket_type);
    rb_define_method (socket_type, "setsockopt", socket_setsockopt, 2);
    rb_define_method (socket_type, "connect", socket_connect, 1);
    rb_define_method (socket_type, "send_string", socket_send, -1);
    rb_define_method (socket_type, "receive_string", socket_recv, -1);
    rb_define_method (socket_type, "close", socket_close, 0);
    rb_define_method (socket_type, "more_parts?", socket_more_parts, 0);

    /*
     *  Stores zmq_poll_item_t for each registered socket. Right now we only
     *  register listeners and only use ZMQ socket objects (no file descriptors)
     */
    VALUE poller_type = rb_define_class_under (zmq_module, "Poller", rb_cObject);
    rb_define_alloc_func (poller_type, poller_alloc);
    rb_define_method (poller_type, "initialize", poller_initialize, 0);
    rb_define_method (poller_type, "register_readable", poller_register_readable, 1);
    rb_define_method (poller_type, "poll", poller_poll, 1);
    rb_define_method (poller_type, "readables", poller_readables, 0);

    rb_define_const (zmq_module, "SUB", INT2NUM (ZMQ_SUB));
    rb_define_const (zmq_module, "DEALER", INT2NUM (ZMQ_DEALER));
    rb_define_const (zmq_module, "SNDMORE", INT2NUM (ZMQ_SNDMORE));
    rb_define_const (zmq_module, "SUBSCRIBE", INT2NUM (ZMQ_SUBSCRIBE));
    rb_define_const (zmq_module, "LINGER", INT2NUM (ZMQ_LINGER));
    rb_define_const (zmq_module, "RCVHWM", INT2NUM (ZMQ_RCVHWM));
    rb_define_const (zmq_module, "SNDHWM", INT2NUM (ZMQ_SNDHWM));
    rb_define_const (zmq_module, "DONTWAIT", INT2NUM (ZMQ_DONTWAIT));
    rb_define_const (zmq_module, "CURVE_SERVERKEY", INT2NUM (ZMQ_CURVE_SERVERKEY));
    rb_define_const (zmq_module, "CURVE_PUBLICKEY", INT2NUM (ZMQ_CURVE_PUBLICKEY));
    rb_define_const (zmq_module, "CURVE_SECRETKEY", INT2NUM (ZMQ_CURVE_SECRETKEY));
}
