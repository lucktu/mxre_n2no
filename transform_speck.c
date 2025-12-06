#include "n2n.h"
#include "n2n_transforms.h"
#include "speck.h"
#include "random.h"

#define N2N_SPECK_TRANSFORM_VERSION   1
#define N2N_SPECK_NONCE_SIZE          16

typedef struct transop_speck {
    speck_context_t ctx;
} transop_speck_t;

int setup_speck_key(void *priv, const uint8_t *encrypt_key, size_t encrypt_key_len) {
    transop_speck_t *speck_priv = (transop_speck_t *)priv;

    if (encrypt_key_len < 32) {
        // Pad key to 32 bytes if shorter
        u_char padded_key[32];
        memset(padded_key, 0, 32);
        memcpy(padded_key, encrypt_key, encrypt_key_len);
        speck_expand_key(padded_key, &speck_priv->ctx);
    } else {
        speck_expand_key(encrypt_key, &speck_priv->ctx);
    }

    return 0;
}

int transop_deinit_speck(n2n_trans_op_t *arg) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    if (priv) {
        free(priv);
    }
    return 0;
}

ssize_t transop_encode_speck(n2n_trans_op_t *arg,
                            uint8_t *outbuf,
                            size_t out_len,
                            const uint8_t *inbuf,
                            size_t in_len) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    uint8_t nonce[N2N_SPECK_NONCE_SIZE];
    size_t idx = 0;

    if (out_len < in_len + N2N_SPECK_NONCE_SIZE + 1) {
        return -1;
    }
    if (!priv || !arg->priv) {
        traceEvent(TRACE_ERROR, "Speck transform not initialized");
        return -1;
    }

    // Version byte
    outbuf[idx++] = N2N_SPECK_TRANSFORM_VERSION;

    // Generate nonce using the random API
    random_bytes(NULL, nonce, N2N_SPECK_NONCE_SIZE);

    // Copy nonce
    memcpy(outbuf + idx, nonce, N2N_SPECK_NONCE_SIZE);
    idx += N2N_SPECK_NONCE_SIZE;

    // Encrypt data
    speck_ctr(outbuf + idx, inbuf, in_len, nonce, &priv->ctx);
    idx += in_len;

    return idx;
}

ssize_t transop_decode_speck(n2n_trans_op_t *arg,
                             uint8_t *outbuf,
                             size_t out_len,
                             const uint8_t *inbuf,
                             size_t in_len) {
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    uint8_t nonce[N2N_SPECK_NONCE_SIZE];
    size_t idx = 0;

    if (in_len < N2N_SPECK_NONCE_SIZE + 1) {
        return -1;
    }

    // Check version
    if (inbuf[idx++] != N2N_SPECK_TRANSFORM_VERSION) {
        return -1;
    }

    // Extract nonce
    memcpy(nonce, inbuf + idx, N2N_SPECK_NONCE_SIZE);
    idx += N2N_SPECK_NONCE_SIZE;

    // Decrypt data
    speck_ctr(outbuf, inbuf + idx, in_len - idx, nonce, &priv->ctx);

    return in_len - idx;
}

n2n_tostat_t transop_tick_speck(n2n_trans_op_t *arg, time_t now) {
    n2n_tostat_t status;
    status.can_tx = 1;
    memset(&status.tx_spec, 0, sizeof(status.tx_spec));
    return status;
}

int transop_addspec_speck(n2n_trans_op_t *arg, const n2n_cipherspec_t *cspec) {
    const char *key_data = (const char *)cspec->opaque;
    transop_speck_t *priv = (transop_speck_t *)arg->priv;
    size_t key_len;

    // Skip "0_" prefix if present
    if (strlen(key_data) > 2 && key_data[0] == '0' && key_data[1] == '_') {
        key_data += 2;
    }

    key_len = strlen(key_data);

    // CRITICAL: Use setup_speck_key instead of speck_expand_key directly
    return setup_speck_key(priv, (const uint8_t *)key_data, key_len);
}

int transop_speck_init(n2n_trans_op_t *ttt) {
    transop_speck_t *priv;

    memset(ttt, 0, sizeof(*ttt));
    ttt->transform_id = N2N_TRANSFORM_ID_SPECK;

    ttt->tick = transop_tick_speck;
    ttt->deinit = transop_deinit_speck;
    ttt->fwd = transop_encode_speck;
    ttt->rev = transop_decode_speck;
    ttt->addspec = transop_addspec_speck;

    priv = (transop_speck_t*)calloc(1, sizeof(transop_speck_t));
    if (!priv) {
        traceEvent(TRACE_ERROR, "cannot allocate transop_speck_t memory");
        return -1;
    }
    ttt->priv = priv;

    traceEvent(TRACE_NORMAL, "Speck transform initialized");
    return 0;
}