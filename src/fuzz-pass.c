#include <stdio.h>
#include <time.h>
#include <linux/input-event-codes.h>

#include "wldbg-private.h"
#include "wldbg-pass.h"
#include "passes.h"
#include "wldbg-parse-message.h"
#include "wayland/wayland-util.h"
#include "wayland/wayland-private.h"

static struct {
    uint32_t keyboard_entered;
    uint32_t pointer_entered;
    uint32_t has_sent;
    uint32_t timestamp;
    uint32_t actual_time;
    uint32_t serial_number;
    uint32_t surface_id; //TODO: Maybe could be multiple surfaces?
    uint32_t pointer_id;
    uint32_t keyboad_id;
    unsigned long last_msg_nanos;
    unsigned char buttons[KEY_MAX];
} fuzz;

static int fuzz_init(struct wldbg *wldbg, struct wldbg_pass *pass, int argc, const char *argv[]) {
    memset(&fuzz, 0, sizeof(fuzz));
    return 0;
}

static int fuzz_in(void *user_data, struct wldbg_message *message) {
    struct wldbg_resolved_message rm;
    if (!wldbg_resolve_message(message, &rm)) {
        return PASS_NEXT;
    }

    uint32_t *buf = message->data;
    uint32_t opcode = buf[1] & 0xffff;

    if (strncmp(rm.wl_interface->name, "wl_keyboard", strlen("wl_keyboard")) == 0) {
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
    }
    if (strncmp(rm.wl_interface->name, "wl_pointer", strlen("wl_pointer")) == 0) {
        if (opcode == 0) {
            fuzz.pointer_id = 1;
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            fuzz.last_msg_nanos = ts.tv_nsec;
            fuzz.serial_number = buf[2];
        }
        if (opcode == 1) {
            fuzz.keyboard_entered = 0;
        }
    }

    return PASS_NEXT;
}

static int fuzz_out(void *user_data, struct wldbg_message *message) {
    struct wldbg_resolved_message rm;
    if (!wldbg_resolve_message(message, &rm)) {
        return PASS_NEXT;
    }

    uint32_t *buf = message->data;
    uint32_t opcode = buf[1] & 0xffff;

    if (strncmp(rm.wl_interface->name, "wl_compositor", strlen("wl_compositor")) == 0) {
        if (opcode == 0) {
            fuzz.surface_id = buf[2];
        }
    }
    else if (strncmp(rm.wl_interface->name, "wl_seat", strlen("wl_seat")) == 0) {
        if (opcode == 0) {
            fuzz.pointer_id = buf[2];
        }
        else if (opcode == 1) {
            fuzz.keyboad_id = buf[2];
        }
    }
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

static int wldbg_fuzz_send_keyboard(struct wldbg *wldbg, unsigned int key, unsigned char pressed) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (!fuzz.keyboard_entered || (ts.tv_nsec - fuzz.last_msg_nanos) < 1000000) {
        return -1;
    }
    struct wldbg_message send_message;
    uint32_t buffer[6];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.keyboad_id;
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

static int wldbg_fuzz_send_button(struct wldbg *wldbg, unsigned int button, unsigned char pressed) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (!fuzz.keyboard_entered || (ts.tv_nsec - fuzz.last_msg_nanos) < 1000000) {
        return -1;
    }
    struct wldbg_message send_message;
    uint32_t buffer[6];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 3;
    buffer[2] = ++(fuzz.serial_number);
    buffer[3] = 0;
    buffer[4] = button;
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

static int wldbg_fuzz_end_pointer_frame(struct wldbg* wldbg) {
    if (!fuzz.keyboard_entered) {
        return -1;
    }
    struct wldbg_message send_message;
    uint32_t buffer[2];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 5;

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

static int wldbg_fuzz_pointer_enter(struct wldbg* wldbg, unsigned int x, unsigned int y) {
    if (!fuzz.surface_id){
        return -1;
    }
    if (fuzz.pointer_entered) {
        return 0;
    }
    struct wldbg_message send_message;
    uint32_t buffer[6];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 0;
    buffer[2] = fuzz.serial_number;
    buffer[3] = fuzz.surface_id;
    buffer[4] = x << 8;
    buffer[5] = y << 8;

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

    fuzz.pointer_entered = 1;

    wldbg_message_print(&send_message);
    return 0;
}

static int wldbg_fuzz_pointer_motion(struct wldbg* wldbg, unsigned int x, unsigned int y) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    if (!fuzz.pointer_entered || (ts.tv_nsec - fuzz.last_msg_nanos) < 1000000) {
        return -1;
    }
    struct wldbg_message send_message;
    uint32_t buffer[5];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 2;
    buffer[2] = 0;
    buffer[3] = x << 8;
    buffer[4] = y << 8;

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
    if (!fuzz.has_sent) {
        if (wldbg_fuzz_pointer_enter(wldbg, 45, 250) == 0) {
            fuzz.serial_number ++;
            if (wldbg_fuzz_send_button(wldbg, BTN_LEFT, pressed) == 0) {
                wldbg_fuzz_end_pointer_frame(wldbg);
                fuzz.buttons[BTN_LEFT] = pressed;
                pressed = 1 - pressed;
                fuzz.has_sent = 1;
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                fuzz.last_msg_nanos = ts.tv_nsec;
            }
        }
    }
}
