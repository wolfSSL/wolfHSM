/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * port/posix/posix_transport_tls.c
 *
 * wolfHSM Transport binding using TLS sockets with wolfSSL
 *
 * This implementation provides basic TLS server functionality using wolfSSL
 * with embedded certificates for authentication.
 */

#include "posix_transport_tls.h"
#include "wolfhsm/wh_error.h"

#if !defined(NO_TLS) && !defined(WOLFCRYPT_ONLY)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>


#ifndef WOLFHSM_CFG_NO_CRYPTO

/* returns 1 (true) if the error passed in is a notice for non blocking
 * 0 if the error is a fatal error */
static int NonBlockingError(int err)
{
    return (err == WOLFSSL_ERROR_WANT_READ) ||
           (err == WOLFSSL_ERROR_WANT_WRITE);
}
#endif /* WOLFHSM_CFG_NO_CRYPTO */

/** Client-side TLS transport functions */

int posixTransportTls_InitConnect(void* context, const void* config,
                                  whCommSetConnectedCb connectcb,
                                  void*                connectcb_arg)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsClientContext* ctx =
        (posixTransportTlsClientContext*)context;
    posixTransportTlsConfig* cfg = (posixTransportTlsConfig*)config;
    int                      rc;
    WOLFSSL_CTX* ssl_ctx;

    if (!ctx || !cfg) {
        return WH_ERROR_BADARGS;
    }

    /* Save configured WOLFSSL_CTX and clear rest of the context struct */
    ssl_ctx = ctx->ssl_ctx;
    memset(ctx, 0, sizeof(posixTransportTlsClientContext));
    ctx->ssl_ctx = ssl_ctx;

    /* Setup underlying TCP transport */
    rc = posixTransportTcp_InitConnect((void*)&ctx->tcpCtx, cfg, connectcb,
                                       connectcb_arg);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    /* At the point of the TCP claiming to be connected, the TLS handshake will
     * happen during send/recv calls */
    if (ctx->connectcb != NULL) {
        ctx->connectcb(ctx->connectcb_arg, WH_COMM_CONNECTED);
    }
    return WH_ERROR_OK;
#else
    (void)context;
    (void)config;
    (void)connectcb;
    (void)connectcb_arg;
    return WH_ERROR_NOTIMPL;
#endif
}

extern int posixTransportTcp_HandleConnect(posixTransportTcpClientContext* c);

int posixTransportTls_SendRequest(void* context, uint16_t size,
                                  const void* data)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsClientContext* ctx =
        (posixTransportTlsClientContext*)context;
    int err;
    int rc = 0;

    if (!ctx || !data || size == 0) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->state != PTTLS_STATE_CONNECTED) {
        if (posixTransportTcp_HandleConnect((void*)&ctx->tcpCtx) !=
            WH_ERROR_OK) {
            return WH_ERROR_NOTREADY;
        }

        /* Create SSL object if not already created
         * (posixTransportTcp_HandleConnect can change the socket used if server
         * is not listening yet, thats why we need to wait to set the fd in
         * wolfSSL until after the connect() has completed) */
        if (ctx->ssl == NULL) {
            if (posixTransportTcp_GetConnectFd(
                    (void*)&ctx->tcpCtx, &ctx->connect_fd_p1) != WH_ERROR_OK) {
                return WH_ERROR_NOTREADY;
            }

            ctx->ssl = wolfSSL_new(ctx->ssl_ctx);
            if (!ctx->ssl) {
                posixTransportTcp_CleanupConnect((void*)&ctx->tcpCtx);
                return WH_ERROR_ABORTED;
            }

            /* Set the current socket file descriptor */
            rc = wolfSSL_set_fd(ctx->ssl, ctx->connect_fd_p1);
            if (rc != WOLFSSL_SUCCESS) {
                wolfSSL_free(ctx->ssl);
                ctx->ssl = NULL;
                posixTransportTcp_CleanupConnect((void*)&ctx->tcpCtx);
                return WH_ERROR_ABORTED;
            }
        }

        rc  = wolfSSL_connect(ctx->ssl);
        err = wolfSSL_get_error(ctx->ssl, rc);
        if (rc != WOLFSSL_SUCCESS) {
            if (NonBlockingError(err)) {
                return WH_ERROR_NOTREADY;
            }
            else {
                if (err == SOCKET_ERROR_E) {
                    /* There is a case where TCP connect() returned successfully
                     * but the server has not called accept() and the pending
                     * send was in the TCP backlog waiting on the server. But
                     * if the server closes down the listen port then RST gets
                     * returned. Retry the TCP connect() */
                     wolfSSL_free(ctx->ssl);
                     ctx->ssl = NULL;

                     /* Close the failed socket fd and set state for retry */
                     if (ctx->tcpCtx.connect_fd_p1 != 0) {
                        close(ctx->tcpCtx.connect_fd_p1 - 1);
                        ctx->tcpCtx.connect_fd_p1 = 0;
                    }
                     ctx->tcpCtx.state = PTT_STATE_UNCONNECTED;
                     return WH_ERROR_NOTREADY;

                }

                if (ctx->connectcb != NULL) {
                    ctx->connectcb(ctx->connectcb_arg, WH_COMM_DISCONNECTED);
                }
                return WH_ERROR_ABORTED;
            }
        }
        else {
            ctx->state = PTTLS_STATE_CONNECTED;
        }
    }

    rc  = wolfSSL_write(ctx->ssl, data, size);
    err = wolfSSL_get_error(ctx->ssl, rc);
    if (rc > 0) {
        return WH_ERROR_OK;
    }
    else if (NonBlockingError(err)) {
        return WH_ERROR_NOTREADY;
    }
    else {
        return WH_ERROR_ABORTED;
    }
#else
    (void)context;
    (void)data;
    (void)size;
    return WH_ERROR_NOTIMPL;
#endif
}

int posixTransportTls_RecvResponse(void* context, uint16_t* out_size,
                                   void* data)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsClientContext* ctx =
        (posixTransportTlsClientContext*)context;
    int rc;
    int err;

    if (!ctx || !data || !out_size) {
        return WH_ERROR_BADARGS;
    }

    /* Create SSL object if not already created */
    if (ctx->ssl == NULL) {
        return WH_ERROR_BADARGS;
    }

    rc  = wolfSSL_read(ctx->ssl, data, PTTLS_PACKET_MAX_SIZE);
    err = wolfSSL_get_error(ctx->ssl, rc);
    if (rc > 0) {
        *out_size = (uint16_t)rc;
        return WH_ERROR_OK;
    }
    else if (NonBlockingError(err)) {
        return WH_ERROR_NOTREADY;
    }
    else {
        return WH_ERROR_ABORTED;
    }

#else
    (void)context;
    (void)data;
    (void)out_size;
    return WH_ERROR_NOTIMPL;
#endif
}

int posixTransportTls_CleanupConnect(void* context)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsClientContext* ctx =
        (posixTransportTlsClientContext*)context;

    if (!ctx) {
        return WH_ERROR_BADARGS;
    }
    if (ctx->ssl) {
        (void)wolfSSL_shutdown(ctx->ssl);
        wolfSSL_free(ctx->ssl);
    }
    ctx->ssl = NULL;
    ctx->state = PTTLS_STATE_UNCONNECTED;
    ctx->connect_fd_p1 = 0;
    posixTransportTcp_CleanupConnect((void*)&ctx->tcpCtx);
    return WH_ERROR_OK;
#else
    (void)context;
    return WH_ERROR_OK;
#endif
}

/** Server-side TLS transport functions */

int posixTransportTls_InitListen(void* context, const void* config,
                                 whCommSetConnectedCb connectcb,
                                 void*                connectcb_arg)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsServerContext* ctx =
        (posixTransportTlsServerContext*)context;
    posixTransportTlsConfig* cfg = (posixTransportTlsConfig*)config;
    int                      rc;
    WOLFSSL_CTX* ssl_ctx;

    if (!ctx || !cfg) {
        return WH_ERROR_BADARGS;
    }

    /* Save configured WOLFSSL_CTX and clear rest of the context struct */
    ssl_ctx = ctx->ssl_ctx;
    memset(ctx, 0, sizeof(posixTransportTlsServerContext));
    ctx->ssl_ctx = ssl_ctx;

    /* Initialize TCP server context */
    rc = posixTransportTcp_InitListen(&ctx->tcpCtx, cfg, connectcb,
                                      connectcb_arg);
    if (rc != WH_ERROR_OK) {
        return rc;
    }

    ctx->connectcb     = connectcb;
    ctx->connectcb_arg = connectcb_arg;
    ctx->server_addr   = ctx->tcpCtx.server_addr;
    ctx->listen_fd_p1  = ctx->tcpCtx.listen_fd_p1;

    if (ctx->connectcb != NULL) {
        ctx->connectcb(ctx->connectcb_arg, WH_COMM_CONNECTED);
    }

    return WH_ERROR_OK;
#else
    (void)context;
    (void)config;
    (void)connectcb;
    (void)connectcb_arg;
    return WH_ERROR_NOTIMPL;
#endif
}

int posixTransportTls_RecvRequest(void* context, uint16_t* out_size, void* data)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsServerContext* ctx =
        (posixTransportTlsServerContext*)context;
    int rc;
    int err;

    if (!ctx || !data || !out_size) {
        return WH_ERROR_BADARGS;
    }

    *out_size = 0;
    /* If no client connected, try to accept one using TCP context */
    if (ctx->accept_fd_p1 == 0) {
        struct sockaddr_in client_addr;
        socklen_t          client_len = sizeof(client_addr);

        rc = accept(ctx->listen_fd_p1 - 1, (struct sockaddr*)&client_addr,
                    &client_len);
        if (rc < 0) {
            switch (errno) {
                case EAGAIN:
                case EINPROGRESS:
                case EINTR:
                    /* Not connected yet or no client */
                    return WH_ERROR_NOTREADY;

                default:
                    return WH_ERROR_ABORTED;
            }
        }
        ctx->accept_fd_p1 = rc + 1;
        ctx->client_addr  = client_addr;

        /* Make accepted socket non-blocking */
        fcntl(ctx->accept_fd_p1 - 1, F_SETFL, O_NONBLOCK);

        /* Create SSL object for this connection */
        ctx->ssl = wolfSSL_new(ctx->ssl_ctx);
        if (!ctx->ssl) {
            return WH_ERROR_ABORTED;
        }

        /* Set the socket file descriptor */
        rc = wolfSSL_set_fd(ctx->ssl, ctx->accept_fd_p1 - 1);
        if (rc != WOLFSSL_SUCCESS) {
            return WH_ERROR_ABORTED;
        }

        /* Perform TLS handshake */
        rc = wolfSSL_accept(ctx->ssl);
        if (rc != WOLFSSL_SUCCESS) {
            int err = wolfSSL_get_error(ctx->ssl, rc);
            if (err == WOLFSSL_ERROR_WANT_READ ||
                err == WOLFSSL_ERROR_WANT_WRITE) {
                return WH_ERROR_NOTREADY;
            }
            return WH_ERROR_ABORTED;
        }

        /* Notify connection established */
        if (ctx->connectcb) {
            ctx->connectcb(ctx->connectcb_arg, WH_COMM_CONNECTED);
        }
    }

    /* Read data from SSL connection */
    rc  = wolfSSL_read(ctx->ssl, data, PTTLS_PACKET_MAX_SIZE);
    err = wolfSSL_get_error(ctx->ssl, rc);
    if (rc > 0) {
        *out_size = (uint16_t)rc;
        return WH_ERROR_OK;
    }
    else if (NonBlockingError(err)) {
        return WH_ERROR_NOTREADY;
    }
    else {
        /* Connection closed */
        return WH_ERROR_ABORTED;
    }
#else
    (void)context;
    (void)data;
    (void)out_size;
    return WH_ERROR_NOTIMPL;
#endif
}

int posixTransportTls_SendResponse(void* context, uint16_t size,
                                   const void* data)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsServerContext* ctx =
        (posixTransportTlsServerContext*)context;
    int rc;

    if (!ctx || !data || size == 0) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->ssl == NULL) {
        return WH_ERROR_NOTREADY;
    }

    /* Send data over SSL connection */
    rc = wolfSSL_write(ctx->ssl, data, size);
    if (rc > 0) {
        return WH_ERROR_OK;
    }
    else {
        int err = wolfSSL_get_error(ctx->ssl, rc);
        if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
            return WH_ERROR_NOTREADY;
        }
        return WH_ERROR_ABORTED;
    }
#else
    (void)context;
    (void)data;
    (void)size;
    return WH_ERROR_NOTIMPL;
#endif
}

int posixTransportTls_CleanupListen(void* context)
{
#ifndef WOLFHSM_CFG_NO_CRYPTO
    posixTransportTlsServerContext* ctx =
        (posixTransportTlsServerContext*)context;

    if (!ctx) {
        return WH_ERROR_BADARGS;
    }

    if (ctx->ssl) {
        /* Give a quick shutdown signal to the client but do not wait for a
         * response from the client before tearing down the transport. */
        (void)wolfSSL_shutdown(ctx->ssl);
        wolfSSL_free(ctx->ssl);
        ctx->ssl = NULL;
    }

    /* Clean up TCP context */
    posixTransportTcp_CleanupListen(&ctx->tcpCtx);

    /* Reset TLS context fields */
    ctx->accept_fd_p1 = 0;
    ctx->listen_fd_p1 = 0;

    return WH_ERROR_OK;
#else
    (void)context;
    return WH_ERROR_OK;
#endif
}

/* Return the file descriptor of the listen socket to support poll/select */
int posixTransportTls_GetListenFd(posixTransportTlsServerContext* context,
                                  int*                            out_fd)
{
    int ret = WH_ERROR_OK;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (context->listen_fd_p1 != 0) {
        if (out_fd != NULL) {
            *out_fd = context->listen_fd_p1 - 1;
        }
    }
    else {
        ret = WH_ERROR_NOTREADY;
    }
    return ret;
}

/* Return the file descriptor of the accepted socket to support poll/select */
int posixTransportTls_GetAcceptFd(posixTransportTlsServerContext* context,
                                  int*                            out_fd)
{
    int ret = WH_ERROR_OK;

    if (context == NULL) {
        return WH_ERROR_BADARGS;
    }

    if (context->accept_fd_p1 != 0) {
        if (out_fd != NULL) {
            *out_fd = context->accept_fd_p1 - 1;
        }
    }
    else {
        ret = WH_ERROR_NOTREADY;
    }
    return ret;
}
#endif /* !defined(NO_TLS) && !defined(WOLFCRYPT_ONLY) */