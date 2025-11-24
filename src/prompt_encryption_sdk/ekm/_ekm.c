#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <openssl/ssl.h>

/*
* SSL_export_keying_material was introduced in OpenSSL 1.0.1.
*/
#define OPENSSL_VERSION_1_0_1 0x10001000L

/* generic: defines the python module name as _ekm */
#define MODULE_NAME "_ekm"

static PyObject *sslsocket_type;

/*
 * --------------------------------------------------------------------------
 * INTERNAL CPYTHON LAYOUT DEPENDENCY
 * --------------------------------------------------------------------------
 * The following struct definition mimics the internal memory layout of
 * CPython's `_ssl.SSLSocket`. This is NOT a public API.
 *
 * We cast the PyObject pointer to this struct to access the raw OpenSSL
 * `SSL*` pointer.
 *
 * COMPATIBILITY NOTE:
 * This layout has been verified to be consistent in CPython versions
 * 3.7 through 3.14 (checked against Modules/_ssl.c).
 *
 * WARNING:
 * A future Python version may change the layout,
 * --------------------------------------------------------------------------
 * This technique of casting PyObject to a struct mimicking CPython's
 * internal _ssl.SSLSocket layout to access the underlying SSL* pointer is
 * also used by other libraries like sslkeylog:
 * https://github.com/segevfiner/sslkeylog/blob/main/_sslkeylog.c
 */
#if PY_MAJOR_VERSION >= 3
typedef struct {
    PyObject_HEAD
    PyObject *Socket; /* weakref to socket on which we're layered */
    SSL *ssl;         /* the raw OpenSSL pointer */
} PySSLSocket;
#else
#error "This module only supports Python 3."
#endif

/*
 * Check for OpenSSL 1.0.1 or later.
 * SSL_export_keying_material was introduced in OpenSSL 1.0.1.
 */
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_1

/*
 * FUNCTION: export_keying_material
 * --------------------------------
 * The actual C function called from Python.
 * Args:
 * m: The module object.
 * args: A tuple containing (sslsocket, label, length, context(optional)).
 */
static PyObject *ekm_export_keying_material(PyObject *m, PyObject *args)
{
    PySSLSocket *sslsocket;
    Py_ssize_t out_length;
    const char *label;
    Py_ssize_t label_length;
    Py_buffer context = {0};
    PyObject *result = NULL;

    /*
     * Parse arguments:
     *   O!: sslsocket object (_ssl._SSLSocket type)
     *   n: out_length (Py_ssize_t)
     *   s#: label (const char *, Py_ssize_t)
     *   |: Denotes optional arguments
     *   z*: context (Py_buffer *, optional)
     * "export_keying_material": function name for error messages
     */
    if (!PyArg_ParseTuple(args, "O!ns#|z*:export_keying_material",
                          sslsocket_type, &sslsocket,
                          &out_length, &label, &label_length, &context)) {
        return NULL;
    }

    /* safety check: ensure the socket is actually connected/handshaked */
    if (!sslsocket->ssl) {
        PyErr_SetString(PyExc_ValueError, "SSLSocket is not connected (no SSL object found)");
        return NULL;
    }

    /* allocate the bytes object for the result */
    result = PyBytes_FromStringAndSize(NULL, out_length);
    if (!result) {
        goto out;
    }

    /*
     * call OpenSSL's native SSL_export_keying_material.
     * it writes directly into the memory buffer of our 'result' Python bytes object.
     */
    if (SSL_export_keying_material(
            sslsocket->ssl,
            (unsigned char *)PyBytes_AS_STRING(result),
            (size_t)out_length,
            label, (size_t)label_length,
            context.buf, context.len, context.buf != NULL) != 1) {
        /* if OpenSSL fails (returns 0 or -1), clear result and raise error */
        Py_CLEAR(result);
        PyErr_SetString(PyExc_RuntimeError, "OpenSSL SSL_export_keying_material failed");
        goto out;
    }

out:
    /* clean up optional context buffer if it was used */
    PyBuffer_Release(&context);
    return result;
}

#endif /* OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_1 */

/* Module method table registration */
static PyMethodDef ekm_methods[] = {
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_1
    {"export_keying_material", ekm_export_keying_material, METH_VARARGS,
     "Exports keying material from an established SSL connection."},
#endif
    {NULL, NULL, 0, NULL}
};

/* Module definition structure */
static PyModuleDef ekm_module = {
    PyModuleDef_HEAD_INIT,
    MODULE_NAME,
    "Low-level C extension to access OpenSSL EKM functions.",
    -1,
    ekm_methods
};

/* Module initialization function */
PyMODINIT_FUNC PyInit__ekm(void)
{
    PyObject *m = NULL;
    PyObject *_ssl = NULL;

    /* create the module */
    m = PyModule_Create(&ekm_module);
    if (!m) goto error;

    /* import standard 'ssl' module to get the standard SSLSocket type for type-checking */
    _ssl = PyImport_ImportModule("_ssl");
    if (!_ssl) goto error;

    sslsocket_type = PyObject_GetAttrString(_ssl, "_SSLSocket");
    if (!sslsocket_type) goto error;

    /* we are done with the module object itself */
    Py_DECREF(_ssl);
    return m;

error:
    Py_XDECREF(_ssl);
    Py_XDECREF(m);
    return NULL;
}