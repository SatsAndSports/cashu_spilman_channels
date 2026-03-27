#include "client_bridge_types.h"

// Go exports for client host callbacks
// Funding Data
extern void go_client_save_channel_funding(void*, const char*, const char*);
extern char* go_client_get_channel_funding(void*, const char*);
// Payment State
extern char* go_client_get_payment_state(void*, const char*);
extern void go_client_record_payment(void*, const char*, const char*);
// Lifecycle
extern char* go_client_get_channel_state(void*, const char*);
extern void go_client_mark_channel_closed(void*, const char*);
extern char* go_client_list_channel_ids(void*);
extern void go_client_delete_channel(void*, const char*);
// Time
extern uint64_t go_client_now_seconds(void*);
// Crypto
extern int go_client_sign_with_tweaked_key(void*, const char*, const char*, const char*, char**);
extern int go_client_compute_channel_secret(void*, const char*, const char*, char**);
// Networking
extern int go_client_call_mint_swap(void*, const char*, const char*, char**);

SpilmanClientHostCallbacks fill_client_callbacks(void* user_data) {
    SpilmanClientHostCallbacks cb;
    cb.user_data = user_data;
    // Funding Data
    cb.save_channel_funding = go_client_save_channel_funding;
    cb.get_channel_funding = go_client_get_channel_funding;
    // Payment State
    cb.get_payment_state = go_client_get_payment_state;
    cb.record_payment = go_client_record_payment;
    // Lifecycle
    cb.get_channel_state = go_client_get_channel_state;
    cb.mark_channel_closed = go_client_mark_channel_closed;
    cb.list_channel_ids = go_client_list_channel_ids;
    cb.delete_channel = go_client_delete_channel;
    // Time
    cb.now_seconds = go_client_now_seconds;
    // Crypto
    cb.sign_with_tweaked_key = go_client_sign_with_tweaked_key;
    cb.compute_channel_secret = go_client_compute_channel_secret;
    // Networking
    cb.call_mint_swap = go_client_call_mint_swap;
    return cb;
}
