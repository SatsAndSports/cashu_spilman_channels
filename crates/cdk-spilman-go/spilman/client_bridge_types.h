#ifndef CLIENT_BRIDGE_TYPES_H
#define CLIENT_BRIDGE_TYPES_H

#include <stdint.h>

typedef struct {
    void* user_data;
    // Channel Opening (two-phase)
    void (*save_opening_channel)(void*, const char*, const char*);    // (channel_id, funding_json)
    void (*mark_channel_open)(void*, const char*, const char*);       // (channel_id, funding_proofs_json)
    char* (*get_channel_funding)(void*, const char*);                 // Returns JSON or NULL
    // Payment State (mutable)
    char* (*get_payment_state)(void*, const char*);                   // Returns JSON or NULL
    void (*record_payment)(void*, const char*, const char*);          // (channel_id, state_json)
    // Lifecycle
    char* (*get_channel_state)(void*, const char*);                   // Returns "opening", "open", or "closed"
    void (*mark_channel_closed)(void*, const char*);
    char* (*list_channel_ids)(void*);
    void (*delete_channel)(void*, const char*);
    // Time
    uint64_t (*now_seconds)(void*);
    // Crypto
    int (*sign_with_tweaked_key)(void*, const char*, const char*, const char*, char**);
    int (*compute_channel_secret)(void*, const char*, const char*, char**);
    // Networking
    int (*call_mint_swap)(void*, const char*, const char*, char**);
    int (*call_mint_restore)(void*, const char*, const char*, char**);
} SpilmanClientHostCallbacks;

#endif
