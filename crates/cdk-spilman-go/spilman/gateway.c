#include <stdint.h>
#include <stdlib.h>

typedef struct {
    char* data;
    char* error;
} CResult;

typedef struct {
    void* user_data;
    int (*receiver_key_is_acceptable)(void*, const char*);
    int (*mint_and_keyset_is_acceptable)(void*, const char*, const char*);
    int (*get_funding_and_params)(void*, const char*, char**, char**, char**, char**);
    void (*save_funding)(void*, const char*, const char*, const char*, const char*, const char*, uint64_t, const char*);
    uint64_t (*get_amount_due)(void*, const char*, const char*);
    void (*record_payment)(void*, const char*, uint64_t, const char*, const char*);
    char* (*get_channel_state)(void*, const char*);
    int (*mark_channel_closing)(void*, const char*, uint64_t, uint64_t, const char*);
    int (*get_closing_data)(void*, const char*, uint64_t*, uint64_t*, char**);
    int (*get_channel_policy)(void*, const char*, uint64_t*, uint64_t*, int64_t*);
    uint64_t (*now_seconds)(void*);
    int (*get_balance_and_signature_for_unilateral_exit)(void*, const char*, uint64_t*, char**);
    char* (*get_active_keyset_ids)(void*, const char*, const char*);
    char* (*get_keyset_info)(void*, const char*, const char*);
    int (*call_mint_swap)(void*, const char*, const char*, char**);
    int (*refresh_all_keysets)(void*, const char*);
    int (*compute_channel_secret)(void*, const char*, const char*, char**);
    int (*sign_with_tweaked_key)(void*, const char*, const char*, const char*, char**);
    int (*mark_channel_closed)(void*, const char*, uint64_t, uint64_t, const char*, const char*, uint64_t, uint64_t);
} SpilmanHostCallbacks;

// Go exports
extern int go_receiver_key_is_acceptable(void*, const char*);
extern int go_mint_and_keyset_is_acceptable(void*, const char*, const char*);
extern int go_get_funding_and_params(void*, const char*, char**, char**, char**, char**);
extern void go_save_funding(void*, const char*, const char*, const char*, const char*, const char*, uint64_t, const char*);
extern uint64_t go_get_amount_due(void*, const char*, const char*);
extern void go_record_payment(void*, const char*, uint64_t, const char*, const char*);
extern char* go_get_channel_state(void*, const char*);
extern int go_mark_channel_closing(void*, const char*, uint64_t, uint64_t, const char*);
extern int go_get_closing_data(void*, const char*, uint64_t*, uint64_t*, char**);
extern int go_get_channel_policy(void*, const char*, uint64_t*, uint64_t*, int64_t*);
extern uint64_t go_now_seconds(void*);
extern int go_get_balance_and_signature_for_unilateral_exit(void*, const char*, uint64_t*, char**);
extern char* go_get_active_keyset_ids(void*, const char*, const char*);
extern char* go_get_keyset_info(void*, const char*, const char*);
extern int go_call_mint_swap(void*, const char*, const char*, char**);
extern int go_refresh_all_keysets(void*, const char*);
extern int go_compute_channel_secret(void*, const char*, const char*, char**);
extern int go_sign_with_tweaked_key(void*, const char*, const char*, const char*, char**);
extern int go_mark_channel_closed(void*, const char*, uint64_t, uint64_t, const char*, const char*, uint64_t, uint64_t);

#include <stdio.h>

SpilmanHostCallbacks fill_callbacks(void* user_data) {
    printf("  [C] fill_callbacks called with user_data=%p\n", user_data);
    SpilmanHostCallbacks cb;
    cb.user_data = user_data;
    cb.receiver_key_is_acceptable = go_receiver_key_is_acceptable;
    cb.mint_and_keyset_is_acceptable = go_mint_and_keyset_is_acceptable;
    cb.get_funding_and_params = go_get_funding_and_params;
    cb.save_funding = go_save_funding;
    cb.get_amount_due = go_get_amount_due;
    cb.record_payment = go_record_payment;
    cb.get_channel_state = go_get_channel_state;
    cb.mark_channel_closing = go_mark_channel_closing;
    cb.get_closing_data = go_get_closing_data;
    cb.get_channel_policy = go_get_channel_policy;
    cb.now_seconds = go_now_seconds;
    cb.get_balance_and_signature_for_unilateral_exit = go_get_balance_and_signature_for_unilateral_exit;
    cb.get_active_keyset_ids = go_get_active_keyset_ids;
    cb.get_keyset_info = go_get_keyset_info;
    cb.call_mint_swap = go_call_mint_swap;
    cb.refresh_all_keysets = go_refresh_all_keysets;
    cb.compute_channel_secret = go_compute_channel_secret;
    cb.sign_with_tweaked_key = go_sign_with_tweaked_key;
    cb.mark_channel_closed = go_mark_channel_closed;
    return cb;
}
