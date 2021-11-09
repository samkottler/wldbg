#include <stdio.h>
#include <time.h>
#include <linux/input-event-codes.h>

#include "wldbg-private.h"
#include "wldbg-pass.h"
#include "passes.h"
#include "wldbg-parse-message.h"
#include "wayland/wayland-util.h"
#include "wayland/wayland-private.h"

#define MILLIS_PER_NANO 1000000

enum event_type {
    KEY,
    MOUSE_ENTER,
    MOUSE_LEAVE,
    MOUSE_BUTTON,
    MOUSE_MOVE
};

struct event {
    enum event_type type;
    unsigned long delay;
    union {
        struct {
            uint32_t key_code, pressed;
        } key;
        struct {
            float x, y;
        } mouse_enter;
        struct {
            uint32_t button_code, pressed;
        } mouse_button;
        struct {
            float x, y;
        } mouse_move;
    };
};

static struct {
    uint32_t keyboard_entered;
    uint32_t pointer_entered;
    uint32_t timestamp;
    uint32_t actual_time;
    uint32_t serial_number;
    uint32_t surface_id; //TODO: Maybe could be multiple surfaces?
    uint32_t pointer_id;
    uint32_t keyboad_id;
    unsigned long last_msg_nanos;
    unsigned long delay;
    unsigned char buttons[KEY_MAX];
    uint32_t num_events;
    uint32_t event_idx;
    struct event* events;
    uint32_t had_first_damage;
    uint32_t displayed;
    uint32_t block_events;
    uint32_t buffer_width;
    uint32_t buffer_height;
} fuzz;

static int fuzz_init(struct wldbg *wldbg, struct wldbg_pass *pass, int argc, const char *argv[]) {
    if (argc < 2) {
        printf("fuzzer needs an events file\n");
        return -1;
    }

    memset(&fuzz, 0, sizeof(fuzz));

    for (int i = 1; i < argc-1; ++i) {
        if (strncmp(argv[i], "block", strlen("block")) == 0) {
            fuzz.block_events = 1;
        }
    }

    FILE* fd = fopen(argv[argc-1], "r");
    if (!fd){
        perror("fopen:");
        return -1;
    }

    fuzz.events = malloc(512 * sizeof(struct event));
    if (!fuzz.events) {
        fclose(fd);
        return -1;
    }

    //TODO: better error checking
    char* line = NULL;
    size_t len = 0;
    fuzz.num_events = 0;
    int serial, ts;
    while (getline(&line, &len, fd) > 0) {
        struct event *event = &(fuzz.events[fuzz.num_events]);
        if (strncmp(line, "KEY", 3) == 0){
            event->type = KEY;
            sscanf(line + 4, "%d,%d,%d,%d\n", &serial, &ts, &(event->key.key_code), &(event->key.pressed));
        }
        if (strncmp(line, "MOTION", 6) == 0) {
            event->type = MOUSE_MOVE;
            sscanf(line + 7, "%d,%f,%f\n", &serial, &(event->mouse_move.x), &(event->mouse_move.y));
        }
        if (strncmp(line, "BUTTON", 6) == 0) {
            sscanf(line + 7, "%d,%d,%d,%d\n", &serial, &ts, &(event->mouse_button.button_code), &(event->mouse_button.pressed));
            event->type = MOUSE_BUTTON;
        }
        if (strncmp(line, "ENTER", 5) == 0) {
            sscanf(line + 6, "%d,%d,%f,%f\n", &serial, &ts, &(event->mouse_enter.x), &(event->mouse_enter.y));
            event->type = MOUSE_ENTER;
        }

        event->delay = 15 * MILLIS_PER_NANO;
        fuzz.num_events ++;
    }
    free(line);

    fclose(fd);
    pass->user_data = wldbg;
    return 0;
}

static int fuzz_in(struct wldbg* wldbg, struct wldbg_message *message) {
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
            fuzz.serial_number = buf[2];
        }
        else if (opcode == 2) {
            fuzz.keyboard_entered = 0;
        }
        else if(opcode == 3){
            if (fuzz.block_events) {
                wldbg->flags.skip = 1;
                return PASS_STOP;
            }
        }
    }
    else if (strncmp(rm.wl_interface->name, "wl_pointer", strlen("wl_pointer")) == 0) {
        if (fuzz.block_events) {
            wldbg->flags.skip = 1;
            return PASS_STOP;
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
    else if (strncmp(rm.wl_interface->name, "wl_surface", strlen("wl_surface")) == 0) {
        if (opcode == 2) {
            fuzz.had_first_damage = 1;
        }
        else if (opcode == 6 && fuzz.had_first_damage) {
            fuzz.displayed = 1;
            //wait 10 miliseconds to make sure everything is ready.
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            fuzz.last_msg_nanos = ts.tv_nsec;
            fuzz.delay = 10000000;
        }
    }
    else if(strncmp(rm.wl_interface->name, "wl_shm_pool", strlen("wl_shm_pool")) == 0) {
        fuzz.buffer_width = buf[4];
        fuzz.buffer_height = buf[5];
    }
    return PASS_NEXT;
}

static void fuzz_destroy(void *user_data) {
    free(fuzz.events);
}

struct pass *create_fuzz_pass() {
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

static int wldbg_fuzz_send_keyboard(struct wldbg *wldbg, unsigned int key, unsigned char pressed) {
    if (!fuzz.keyboard_entered) {
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
    if (!fuzz.keyboard_entered) {
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

static int wldbg_fuzz_pointer_enter(struct wldbg* wldbg, float x, float y) {
    if (!fuzz.surface_id){
        return -1;
    }
    if (fuzz.pointer_entered) {
        return 0;
    }
    uint32_t real_x = fuzz.buffer_width * x;
    uint32_t real_y = fuzz.buffer_height * y;
    struct wldbg_message send_message;
    uint32_t buffer[6];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 0;
    buffer[2] = ++(fuzz.serial_number);
    buffer[3] = fuzz.surface_id;
    buffer[4] = real_x << 8;
    buffer[5] = real_y << 8;

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

static int wldbg_fuzz_pointer_motion(struct wldbg* wldbg, float x, float y) {
    uint32_t real_x = fuzz.buffer_width * x;
    uint32_t real_y = fuzz.buffer_height * y;
    struct wldbg_message send_message;
    uint32_t buffer[5];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 2;
    buffer[2] = 0;
    buffer[3] = real_x << 8;
    buffer[4] = real_y << 8;

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
    if (fuzz.event_idx < fuzz.num_events) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        if (fuzz.delay + fuzz.last_msg_nanos > ts.tv_nsec) {
            return 0;
        }

        struct event* event = &(fuzz.events[fuzz.event_idx]);
        switch (event->type) {
            case KEY:
                if (wldbg_fuzz_send_keyboard(wldbg, event->key.key_code, event->key.pressed)) {
                    return -1;
                }
                break;
            case MOUSE_BUTTON:
                if (wldbg_fuzz_send_button(wldbg, event->mouse_button.button_code, event->mouse_button.pressed)) {
                    return -1;
                }
                if (wldbg_fuzz_end_pointer_frame(wldbg)) {
                    return -1;
                }
                break;
            case MOUSE_MOVE:
                if (wldbg_fuzz_pointer_motion(wldbg, event->mouse_move.x, event->mouse_move.y)){
                    return 1;
                }
                if (wldbg_fuzz_end_pointer_frame(wldbg)) {
                    return -1;
                }
                break;
            case MOUSE_ENTER:
                if (wldbg_fuzz_pointer_enter(wldbg, event->mouse_enter.x, event->mouse_enter.y)) {
                    return -1;
                }
                if (wldbg_fuzz_end_pointer_frame(wldbg)) {
                    return -1;
                }
                break;
        }

        fuzz.event_idx ++;
        fuzz.delay = event->delay;

        clock_gettime(CLOCK_MONOTONIC, &ts);
        fuzz.last_msg_nanos = ts.tv_nsec;
    }
    return 0;
}
