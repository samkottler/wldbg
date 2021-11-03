#include <stdio.h>
#include <time.h>

#include "wldbg-private.h"
#include "wldbg-pass.h"
#include "passes.h"
#include "wldbg-parse-message.h"
#include "wayland/wayland-util.h"
#include "wayland/wayland-private.h"

static struct {
    uint32_t keyboard_entered;
    uint32_t has_sent;
    uint32_t timestamp;
    uint32_t actual_time;
    uint32_t serial_number;
    unsigned long last_msg_nanos;
    unsigned char key_status[256];
} fuzz;

static int fuzz_init(struct wldbg *wldbg, struct wldbg_pass *pass, int argc, const char *argv[]) {
    fuzz.keyboard_entered = 0;
    fuzz.has_sent = 0;
    for (int i = 0; i < 256; ++i){
        fuzz.key_status[i] = 0;
    }
    return 0;
}

static int fuzz_in(void *user_data, struct wldbg_message *message) {
    struct wldbg_resolved_message rm;
    if (!wldbg_resolve_message(message, &rm)) {
        return PASS_NEXT;
    }
    if (message->from == CLIENT) {
        return PASS_NEXT;
    }
    char* interface_name = "wl_keyboard";
    if (strncmp(rm.wl_interface->name, interface_name, strlen(interface_name))) {
//         printf("%s\n", rm.wl_interface->name);
        return PASS_NEXT;
    }
    uint32_t *buf = message->data;
    uint32_t opcode = buf[1] & 0xffff;
    if (opcode == 1) {
        //TODO: update fuzz.key_status
        fuzz.keyboard_entered = 1;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        fuzz.last_msg_nanos = ts.tv_nsec;
        fuzz.serial_number = buf[2];
    }
    if (opcode == 2) {
        fuzz.keyboard_entered = 0;
    }
    return PASS_NEXT;
}

static int fuzz_out(void *user_data, struct wldbg_message *message) {
    return PASS_NEXT;
}

static void fuzz_destroy(void *user_data) {

}

static struct pass *create_fuzz_pass() {
    struct pass *pass;

    pass = alloc_pass("fuzz");
    if (!pass)
        return NULL;

    pass->wldbg_pass.init = fuzz_init;
    pass->wldbg_pass.destroy = fuzz_destroy;
    pass->wldbg_pass.server_pass = fuzz_in;
    pass->wldbg_pass.client_pass = fuzz_out;
    pass->wldbg_pass.description = "Pass to help keep track of info for fuzz testing";

    return pass;
}

int wldbg_add_fuzz_pass(struct wldbg* wldbg) {
    struct pass *pass = create_fuzz_pass();
    if (!pass) {
        return -1;
    }

    if (fuzz_init(wldbg, &(pass->wldbg_pass), 0, NULL) < 0) {
        dealloc_pass(pass);
        return -1;
    }

    wl_list_insert(&(wldbg->passes), &(pass->link));

    return 0;
}

static int wldbg_fuzz_send_keyboard(struct wldbg *wldbg, unsigned char key, unsigned char pressed) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (!fuzz.keyboard_entered || (ts.tv_nsec - fuzz.last_msg_nanos) < 1000000){
        return -1;
    }
    struct wldbg_message send_message;
    uint32_t buffer[6];
    uint32_t size = sizeof(buffer);
    buffer[0] = 3;
    buffer[1] = (size << 16) | 3;
    buffer[2] = ++(fuzz.serial_number);
    buffer[3] = 0;
    buffer[4] = key;
    buffer[5] = pressed;

    send_message.connection = wldbg->message.connection;
    send_message.data = buffer;
    send_message.size = size;
    send_message.from = SERVER;

    struct wl_connection *conn = wldbg->message.connection->client.connection;

    if (wl_connection_write(conn, buffer, size) < 0) {
        perror("Writing message to connection");
        return -1;
    }
    if (wl_connection_flush(conn) < 0) {
        perror("wl_connection_flush");
        return -1;
    }
    wldbg_message_print(&send_message);
    return 0;
}

int wldbg_fuzz_send_next(struct wldbg *wldbg) {
    static uint32_t pressed = 1;
    if ((fuzz.has_sent && fuzz.key_status[2]) ||!fuzz.has_sent) {
        if (wldbg_fuzz_send_keyboard(wldbg, 2, pressed) == 0) {
            fuzz.key_status[2] = pressed;
            pressed = 1 - pressed;
            fuzz.has_sent = 1;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            fuzz.last_msg_nanos = ts.tv_nsec;
        }
    }
}
