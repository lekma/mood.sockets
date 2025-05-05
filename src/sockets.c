#define PY_SSIZE_T_CLEAN
#include "Python.h"
#include "structmember.h"


#include "helpers/helpers.h"


#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>


/* -------------------------------------------------------------------------- */

#define SOCK_FLAGS (SOCK_CLOEXEC | SOCK_NONBLOCK)
#define SOCK_TYPE (SOCK_STREAM | SOCK_CLOEXEC)

#define ABSTRACT_MARKER L'@'

#define SIZEOF_SUN_PATH sizeof(((struct sockaddr_un *)0)->sun_path)
#define OFFSETOF_SUN_PATH offsetof(struct sockaddr_un, sun_path)


/* -------------------------------------------------------------------------- */

/* Socket */
typedef struct {
    PyObject_HEAD
    int fd;
    Py_ssize_t wsize;
    PyObject *address;
} Socket;


/* -------------------------------------------------------------------------- */

#define __sys_getsockopt__(...) \
    __sys_gil_wrap__(int, getsockopt, __VA_ARGS__)
#define __sys_setsockopt__(...) \
    __sys_gil_wrap__(int, setsockopt, __VA_ARGS__)

#define __sys_ioctl__(...) \
    __sys_gil_wrap__(int, ioctl, __VA_ARGS__)

#define __sys_getaddrinfo__(...) \
    __sys_gil_wrap__(int, getaddrinfo, __VA_ARGS__)
#define __sys_inet_pton__(...) \
    __sys_gil_wrap__(int, inet_pton, __VA_ARGS__)
#define __sys_inet_ntop__(...) \
    __sys_gil_wrap__(const char *, inet_ntop, __VA_ARGS__)

#define __sys_socket__(...) \
    __sys_gil_wrap__(int, socket, __VA_ARGS__)
#define __sys_connect__(...) \
    __sys_gil_wrap__(int, connect, __VA_ARGS__)
#define __sys_bind__(...) \
    __sys_gil_wrap__(int, bind, __VA_ARGS__)
#define __sys_listen__(...) \
    __sys_gil_wrap__(int, listen, __VA_ARGS__)
#define __sys_accept__(...) \
    __sys_gil_wrap__(int, accept4, __VA_ARGS__)
/*
#define __sys_close__(...) \
    __sys_gil_wrap__(int, close, __VA_ARGS__)
*/
#define __sys_close__ close

#define __sys_read__(...) \
    __sys_gil_wrap__(ssize_t, read, __VA_ARGS__)
#define __sys_write__(...) \
    __sys_gil_wrap__(ssize_t, write, __VA_ARGS__)


/* -------------------------------------------------------------------------- */

static int
__getsockopt__(int fd, int op)
{
    int result;
    socklen_t resultlen = sizeof(int);

    if (__sys_getsockopt__(fd, SOL_SOCKET, op, &result, &resultlen)) {
        _PyErr_SetFromErrno();
        return -1;
    }
    return result;
}

static int
__setsockopt__(int fd, int op, int *value)
{
    int result = -1;
    socklen_t valuelen = sizeof(int);

    if ((result = __sys_setsockopt__(fd, SOL_SOCKET, op, value, valuelen))) {
        _PyErr_SetFromErrno();
    }
    return result;
}


static int
__ioctl__(int fd, int op, void *value)
{
    int result = -1;

    if ((result = __sys_ioctl__(fd, op, value)) < 0) {
        _PyErr_SetFromErrno();
    }
    return result;
}


static struct addrinfo *
__getaddrinfo__(const char *host, const char *port, struct addrinfo *hints)
{
    int error;
    struct addrinfo *results = NULL;

    hints->ai_family = AF_INET;
    hints->ai_socktype = SOCK_STREAM;

    if ((error = __sys_getaddrinfo__(host, port, hints, &results))) {
        PyErr_SetString(PyExc_OSError, gai_strerror(error));
        results = NULL; // ??
    }
    return results; // use freeaddrinfo() on results when done
}

static int
__inet_pton__(const char *src, struct in_addr *dst)
{
    int result = -1;

    if ((result = __sys_inet_pton__(AF_INET, src, dst)) < 0) {
        _PyErr_SetFromErrno();
    }
    return result;
}

static const char *
__inet_ntop__(const struct in_addr *src, char *dst, socklen_t len)
{
    const char *result = NULL;

    if (!(result = __sys_inet_ntop__(AF_INET, src, dst, len))) {
        _PyErr_SetFromErrno();
    }
    return result;
}


static int
__socket__(int family)
{
    int result = -1;

    if ((result = __sys_socket__(family, SOCK_TYPE, 0)) == -1) {
        _PyErr_SetFromErrno();
    }
    return result;
}

static int
__connect__(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int result = -1;

    if ((result = __sys_connect__(fd, addr, addrlen))) {
        _PyErr_SetFromErrno();
    }
    return result;
}

static int
__bind__(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    int result = -1;

    if ((result = __sys_bind__(fd, addr, addrlen))) {
        _PyErr_SetFromErrno();
    }
    return result;
}

static int
__listen__(int fd)
{
    int result = -1;

    if ((result = __sys_listen__(fd, SOMAXCONN))) {
        _PyErr_SetFromErrno();
    }
    return result;
}

static int
__accept__(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    int result = -1;

    if ((result = __sys_accept__(fd, addr, addrlen, SOCK_FLAGS)) == -1) {
        _PyErr_SetFromErrno();
    }
    return result;
}

static int
__close__(int fd)
{
    int result = -1;
    int chain = (PyErr_Occurred() ? 1 : 0);

    if ((result = __sys_close__(fd))) {
        if (chain) {
            _PyErr_SetFromErrnoAndChain();
        }
        else {
            _PyErr_SetFromErrno();
        }
    }
    return result;
}


static ssize_t
__read__(int fd, void *buf, size_t count)
{
    ssize_t result = -1;

    if ((result = __sys_read__(fd, buf, count)) < 0) {
        _PyErr_SetFromErrno();
    }
    return result;
}

static ssize_t
__write__(int fd, const void *buf, size_t count)
{
    ssize_t result = -1;

    if ((result = __sys_write__(fd, buf, count)) < 0) {
        _PyErr_SetFromErrno();
    }
    return result;
}


/* addr -> address ---------------------------------------------------------- */

static PyObject *
__address_unix__(struct sockaddr_un *addr)
{
    if (addr->sun_path[0] == 0) {  /* Linux abstract namespace */
        return PyUnicode_FromFormat("@%s", addr->sun_path + 1);
    }
    return PyUnicode_DecodeFSDefault(addr->sun_path);
}


static PyObject *
__address_inet__(struct sockaddr_in *addr)
{
    char ip[INET_ADDRSTRLEN];

    if (!__inet_ntop__(&addr->sin_addr, ip, INET_ADDRSTRLEN)) {
        return NULL;
    }
    return Py_BuildValue("sH", ip, ntohs(addr->sin_port));
}


static PyObject *
__address__(struct sockaddr *addr)
{
    PyObject *address = NULL;

    switch (addr->sa_family) {
        case AF_UNIX:
            address = __address_unix__((struct sockaddr_un *)addr);
            break;
        case AF_INET:
            address = __address_inet__((struct sockaddr_in *)addr);
            break;
        default:
            PyErr_SetString(PyExc_ValueError, "unsupported protocol family");
            break;
    }
    return address;
}


/* address -> addr ---------------------------------------------------------- */

static socklen_t
__addr_unix__(PyObject *address, struct sockaddr_un *addr, int server)
{
    Py_ssize_t abstract = -2;
    PyObject *_address_ = NULL;
    Py_ssize_t size = 0;
    const char *data = NULL;

    if (!PyUnicode_GET_LENGTH(address)) {
        PyErr_SetString(PyExc_ValueError, "empty name");
        return 0;
    }
    if ((abstract = PyUnicode_FindChar(address, ABSTRACT_MARKER, 0, 1, 1))) {
        if (abstract != -1) {
            return 0;
        }
        // path
        _address_ = PyUnicode_EncodeFSDefault(address);
    }
    else {
        // abstract
        _address_ = PyUnicode_AsUTF8String(address);
    }
    if (!_address_) {
        return 0;
    }
    abstract += 1;
    size = PyBytes_GET_SIZE(_address_) - abstract;
    data = PyBytes_AS_STRING(_address_) + abstract;
    if ((size_t)size != strlen(data)) {
        PyErr_SetString(PyExc_ValueError, "embedded null byte");
        Py_CLEAR(_address_);
        return 0;
    }
    if ((size_t)size >= (SIZEOF_SUN_PATH - abstract)) {
        PyErr_SetString(PyExc_OverflowError, "name too long");
        Py_CLEAR(_address_);
        return 0;
    }
    memcpy(addr->sun_path + abstract , data, size);
    addr->sun_family = AF_UNIX;
    Py_CLEAR(_address_);
    return (OFFSETOF_SUN_PATH + size + 1);
}


static struct addrinfo *
__inet_info__(const char *host, int server)
{
    struct addrinfo hints = { 0 };

    hints.ai_flags = AI_NUMERICSERV;
    if (server) {
        hints.ai_flags |= AI_PASSIVE;
    }
    return __getaddrinfo__(host, "0", &hints);
}

static socklen_t
__addr_inet__(PyObject *address, struct sockaddr_in *addr, int server)
{
    PyObject *host = NULL, *port = NULL, *_host_ = NULL;
    unsigned long _port_;
    const char *data = NULL;
    int res = 0;
    struct addrinfo *results = NULL;

    if (!PyArg_ParseTuple(address, "OO:__init__", &host, &port)) {
        return 0;
    }
    // port
    _port_ = PyLong_AsUnsignedLong(port);
    if (PyErr_Occurred()) {
        return 0;
    }
    if (_port_ > USHRT_MAX) {
        PyErr_Format(PyExc_OverflowError, "port must be 0-%u", USHRT_MAX);
        return 0;
    }
    addr->sin_port = htons((unsigned short)_port_);
    // host
    if (!(_host_ = PyUnicode_AsEncodedString(host, "idna", NULL))) {
        return 0;
    }
    if (PyBytes_GET_SIZE(_host_)) {
        data = PyBytes_AS_STRING(_host_);
    }
    if (data && (res = __inet_pton__(data, &addr->sin_addr)) < 0) {
        Py_CLEAR(_host_);
        return 0;
    }
    else if (!res) {
        if (!(results = __inet_info__(data, server))) {
            Py_CLEAR(_host_);
            return 0;
        }
        addr->sin_addr.s_addr =
            ((struct sockaddr_in *)results->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(results);
    }
    addr->sin_family = AF_INET;
    Py_CLEAR(_host_);
    return sizeof(struct sockaddr_in);
}


static socklen_t
__addr__(PyObject *address, struct sockaddr *addr, int server)
{
    socklen_t addrlen = 0;

    if (PyUnicode_Check(address)) {
        addrlen = __addr_unix__(address, (struct sockaddr_un *)addr, server);
    }
    else if (PyTuple_Check(address)) {
        addrlen = __addr_inet__(address, (struct sockaddr_in *)addr, server);
    }
    else {
        PyErr_Format(
            PyExc_TypeError,
            "expected tuple or string, got: %.200s",
            Py_TYPE(address)->tp_name
        );
    }
    return addrlen;
}


/* -------------------------------------------------------------------------- */

static int
__socket_create__(struct sockaddr *addr, socklen_t addrlen, int server)
{
    int fd = -1;
    int _true_ = 1;

    if ((fd = __socket__(addr->sa_family)) != -1) {
        if (server) {
            // reuse address/port
            if (
                addr->sa_family == AF_INET &&
                (
                    __setsockopt__(fd, SO_REUSEADDR, &_true_) ||
                    __setsockopt__(fd, SO_REUSEPORT, &_true_)
                )
            ) {
                goto fail;
            }
            // bind / listen
            if (
                __bind__(fd, addr, addrlen) ||
                __listen__(fd)
            ) {
                goto fail;
            }
        }
        else {
            // autobind feature
            if (
                addr->sa_family == AF_UNIX &&
                __setsockopt__(fd, SO_PASSCRED, &_true_)
            ) {
                goto fail;
            }
            // connect
            if (__connect__(fd, addr, addrlen)) {
                goto fail;
            }
        }
        // non blocking
        if (__ioctl__(fd, FIONBIO, &_true_)) {
            goto fail;
        }
    }
    goto exit;

fail:
    __close__(fd);
    fd = -1;

exit:
    return fd;
}


/* --------------------------------------------------------------------------
    Socket
   -------------------------------------------------------------------------- */

static Socket *
__Socket_alloc__(PyTypeObject *type)
{
    Socket *self = NULL;

    if ((self = PyObject_GC_NEW(Socket, type))) {
        self->fd = -1;
        self->wsize = -1;
        self->address = NULL;
        PyObject_GC_Track(self);
    }
    return self;
}


static int
__Socket_setup__(Socket *self, int fd, struct sockaddr *addr)
{
    int wsize = -1;

    if (
        !(self->address = __address__(addr)) ||
        ((wsize = __getsockopt__(fd, SO_SNDBUF)) < 0)
    ) {
        __close__(fd);
        return -1;
    }
    self->wsize = ((wsize / 2) & ~7);
    self->fd = fd;
    return 0;
}


static int
__Socket_close__(Socket *self)
{
    int res = 0;

    if (self->fd != -1) {
        res = __close__(self->fd);
        self->fd = -1;
    }
    return res;
}

static int
__Socket_init__(Socket *self, PyObject *args, int server)
{
    PyObject *address = NULL;
    struct sockaddr_storage saddr = {0};
    struct sockaddr *addr = (struct sockaddr *)&saddr;
    socklen_t addrlen = 0;
    int fd = -1;

    if (
        !PyArg_ParseTuple(args, "O:__init__", &address) ||
        !(addrlen = __addr__(address, addr, server)) ||
        ((fd = __socket_create__(addr, addrlen, server)) == -1)
    ) {
        return -1;
    }
    return __Socket_setup__(self, fd, addr);
}


static Socket *
__Socket_new__(PyTypeObject *type, int fd, struct sockaddr *addr)
{
    Socket *self = NULL;

    if ((self = __Socket_alloc__(type)) && __Socket_setup__(self, fd, addr)) {
        Py_CLEAR(self);
    }
    return self;
}


/* -------------------------------------------------------------------------- */

/* [ClientSocket, ServerSocket]_Type.tp_new */
static PyObject *
Socket_tp_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return (PyObject *)__Socket_alloc__(type);
}


/* Socket_Type -------------------------------------------------------------- */

/* Socket.close() */
static PyObject *
Socket_close(Socket *self)
{
    if (__Socket_close__(self)) {
        return NULL;
    }
    Py_RETURN_NONE;
}


/* Socket.fileno() */
static PyObject *
Socket_fileno(Socket *self)
{
    return PyLong_FromLong(self->fd);
}


/* Socket_Type.tp_methods */
static PyMethodDef Socket_tp_methods[] = {
    {"close", (PyCFunction)Socket_close, METH_NOARGS, "close()"},
    {"fileno", (PyCFunction)Socket_fileno, METH_NOARGS, "fileno() -> int"},
    {NULL}  /* Sentinel */
};


/* -------------------------------------------------------------------------- */

/* SocketType.tp_members */
static PyMemberDef Socket_tp_members[] = {
    {"address", T_OBJECT_EX, offsetof(Socket, address), READONLY, NULL},
    {NULL}  /* Sentinel */
};


/* -------------------------------------------------------------------------- */

/* Socket.closed */
static PyObject *
Socket_closed_get(Socket *self, void *closure)
{
    return PyBool_FromLong((self->fd == -1));
}


/* Socket_Type.tp_getset */
static PyGetSetDef Socket_tp_getset[] = {
    {"closed", (getter)Socket_closed_get,_Py_READONLY_ATTRIBUTE, NULL, NULL},
    {NULL}  /* Sentinel */
};


/* -------------------------------------------------------------------------- */

/* Socket_Type.tp_traverse */
static int
Socket_tp_traverse(Socket *self, visitproc visit, void *arg)
{
    Py_VISIT(self->address);
    return 0;
}


/* Socket_Type.tp_finalize */
static void
Socket_tp_finalize(Socket *self)
{
    PyObject *exc_type, *exc_value, *exc_traceback;

    PyErr_Fetch(&exc_type, &exc_value, &exc_traceback);
    if (__Socket_close__(self)) {
        PyErr_WriteUnraisable((PyObject *)self);
    }
    PyErr_Restore(exc_type, exc_value, exc_traceback);
}


/* Socket_Type.tp_clear */
static int
Socket_tp_clear(Socket *self)
{
    Py_CLEAR(self->address);
    return 0;
}


/* Socket_Type.tp_dealloc */
static void
Socket_tp_dealloc(Socket *self)
{
    if (PyObject_CallFinalizerFromDealloc((PyObject *)self)) {
        return;
    }
    PyObject_GC_UnTrack(self);
    Socket_tp_clear(self);
    PyObject_GC_Del(self);
}


/* Socket_Type.tp_repr */
static PyObject *
Socket_tp_repr(Socket *self)
{
    return PyUnicode_FromFormat(
        "<%s(address=%R, fd=%d)>",
        Py_TYPE(self)->tp_name,
        self->address,
        self->fd
    );
}


/* -------------------------------------------------------------------------- */

static PyTypeObject Socket_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "mood.sockets.Socket",
    .tp_basicsize = sizeof(Socket),
    .tp_dealloc = (destructor)Socket_tp_dealloc,
    .tp_repr = (reprfunc)Socket_tp_repr,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC | Py_TPFLAGS_HAVE_FINALIZE,
    .tp_traverse = (traverseproc)Socket_tp_traverse,
    .tp_clear = (inquiry)Socket_tp_clear,
    .tp_methods = Socket_tp_methods,
    .tp_members = Socket_tp_members,
    .tp_getset = Socket_tp_getset,
    .tp_finalize = (destructor)Socket_tp_finalize,
};


/* --------------------------------------------------------------------------
    ClientSocket
   -------------------------------------------------------------------------- */

static inline Py_ssize_t
__buf_terminate__(PyByteArrayObject *buf, Py_ssize_t size)
{
    Py_SIZE(buf) = size;
    buf->ob_start[size] = '\0';
    return size;
}


static inline int
__buf_realloc__(PyByteArrayObject *buf, Py_ssize_t nalloc)
{
    Py_ssize_t alloc = 0;
    void *bytes = NULL;

    if (buf->ob_alloc < nalloc) {
        alloc = Py_MAX(nalloc, (buf->ob_alloc << 1));
        if (!(bytes = PyObject_Realloc(buf->ob_bytes, alloc))) {
            return -1;
        }
        buf->ob_start = buf->ob_bytes = bytes;
        buf->ob_alloc = alloc;
    }
    return 0;
}


static inline int
__buf_resize__(PyByteArrayObject *buf, size_t size)
{
    if ((size >= PY_SSIZE_T_MAX) || __buf_realloc__(buf, (size + 1))) {
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}


/* ClientSocket_Type -------------------------------------------------------- */

/* ClientSocket.write(buf) */
static PyObject *
ClientSocket_write(Socket *self, PyObject *args)
{
    PyByteArrayObject *buf = NULL;
    Py_ssize_t len = 0, size = -1;

    if (!PyArg_ParseTuple(args, "Y:write", &buf)) {
        return NULL;
    }
    len = Py_SIZE(buf);
    while (len > 0) {
        size = __write__(self->fd, buf->ob_start, Py_MIN(len, self->wsize));
        if (size == -1) {
            return NULL;
        }
        // XXX: very bad shortcut ¯\_(ツ)_/¯
        buf->ob_start += size;
        len = __buf_terminate__(buf, (len - size));
    }
    Py_RETURN_NONE;
}


/* ClientSocket.read(buf) */
static PyObject *
ClientSocket_read(Socket *self, PyObject *args)
{
    PyByteArrayObject *buf = NULL;
    Py_ssize_t len = 0, size = -1;
    int nread = 0;

    if (!PyArg_ParseTuple(args, "Y:read", &buf)) {
        return NULL;
    }
    len = Py_SIZE(buf);
    if (__ioctl__(self->fd, FIONREAD, &nread)) {
        return NULL;
    }
    if (nread && __buf_resize__(buf, (len + nread))) {
        return NULL;
    }
    do {
        size = __read__(self->fd, (buf->ob_start + len), nread);
        if (size == -1) {
            return NULL;
        }
        if (size) {
            nread -= size;
            len = __buf_terminate__(buf, (len + size));
        }
    } while (nread > 0);
    return PyBool_FromLong((size == 0));
}


/* ClientSocket_Type.tp_methods */
static PyMethodDef ClientSocket_tp_methods[] = {
    {"write", (PyCFunction)ClientSocket_write, METH_VARARGS, "write(buf)"},
    {"read", (PyCFunction)ClientSocket_read, METH_VARARGS, "read(buf) -> bool"},
    {NULL}  /* Sentinel */
};


/* -------------------------------------------------------------------------- */

/* ClientSocket_Type.tp_init */
static int
ClientSocket_tp_init(Socket *self, PyObject *args, PyObject *kwargs)
{
    return __Socket_init__(self, args, 0);
}


/* -------------------------------------------------------------------------- */

static PyTypeObject ClientSocket_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "mood.sockets.ClientSocket",
    .tp_basicsize = sizeof(Socket),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_methods = ClientSocket_tp_methods,
    .tp_init = (initproc)ClientSocket_tp_init,
    .tp_new = Socket_tp_new,
};


/* --------------------------------------------------------------------------
    ServerSocket
   -------------------------------------------------------------------------- */

/* ServerSocket_Type -------------------------------------------------------- */

/* ServerSocket.accept() */
static PyObject *
ServerSocket_accept(Socket *self)
{
    struct sockaddr_storage saddr = {0};
    struct sockaddr *addr = (struct sockaddr *)&saddr;
    socklen_t addrlen = sizeof(struct sockaddr_storage); // static const?
    int fd = -1;

    if ((fd = __accept__(self->fd, addr, &addrlen)) == -1) {
        return NULL;
    }
    return (PyObject *)__Socket_new__(&ClientSocket_Type, fd, addr);
}


/* ServerSocket_Type.tp_methods */
static PyMethodDef ServerSocket_tp_methods[] = {
    {"accept", (PyCFunction)ServerSocket_accept,  METH_NOARGS, "accept() -> sock"},
    {NULL}  /* Sentinel */
};


/* -------------------------------------------------------------------------- */

/* ServerSocket_Type.tp_init */
static int
ServerSocket_tp_init(Socket *self, PyObject *args, PyObject *kwargs)
{
    return __Socket_init__(self, args, 1);
}


/* -------------------------------------------------------------------------- */

static PyTypeObject ServerSocket_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "mood.sockets.ServerSocket",
    .tp_basicsize = sizeof(Socket),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_methods = ServerSocket_tp_methods,
    .tp_init = (initproc)ServerSocket_tp_init,
    .tp_new = Socket_tp_new,
};


/* --------------------------------------------------------------------------
    module
   -------------------------------------------------------------------------- */

/* sockets_def */
static PyModuleDef sockets_def = {
    PyModuleDef_HEAD_INIT,
    .m_name = "sockets",
    .m_doc = "mood sockets module",
    .m_size = -1,
};


/* module initialization */
static inline int
__module_init__(PyObject *module)
{
    if (
        PyType_Ready(&Socket_Type) ||
        _PyModule_AddTypeWithBase(module, &ClientSocket_Type, &Socket_Type) ||
        _PyModule_AddTypeWithBase(module, &ServerSocket_Type, &Socket_Type) ||
        PyModule_AddStringConstant(module, "__version__", PKG_VERSION)
    ) {
        return -1;
    }

    return 0;
}

PyMODINIT_FUNC
PyInit_sockets(void)
{
    PyObject *module = NULL;

    if ((module = PyState_FindModule(&sockets_def))) {
        Py_INCREF(module);
    }
    else if (
        (module = PyModule_Create(&sockets_def)) && __module_init__(module)
    ) {
        Py_CLEAR(module);
    }
    return module;
}
