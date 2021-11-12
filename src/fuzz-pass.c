#include <stdio.h>
#include <time.h>
#include <linux/input-event-codes.h>

#include "wldbg-private.h"
#include "wldbg-pass.h"
#include "passes.h"
#include "wldbg-parse-message.h"
#include "wayland/wayland-util.h"
#include "wayland/wayland-private.h"

#define MILLIS_PER_SEC 1000
#define NANOS_PER_MILLI 1000000

#define INTERFACE_MATCHES(strname) (strcmp(rm.wl_interface->name, (strname)) == 0)

enum event_type {
    KEY,
    MOUSE_ENTER,
    MOUSE_LEAVE,
    MOUSE_BUTTON,
    MOUSE_MOVE
};

struct event {
    enum event_type type;
    struct timespec delay;
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

struct serial_message {
    char* name;
    uint32_t opcode;
    uint32_t serial_index;
};

static struct serial_message server_serials[] = {
    {"wl_data_device", 1, 2},
    {"wl_shell_surface", 0, 2},
    {"wl_pointer", 0, 2},
    {"wl_pointer", 1, 2},
    {"wl_pointer", 3, 2},
    {"wl_keyboard", 1, 2},
    {"wl_keyboard", 2, 2},
    {"wl_keyboard", 3, 2},
    {"wl_keyboard", 4, 2},
    {"wl_touch", 0, 2},
    {"wl_touch", 1, 2}
};

static struct serial_message client_serials[] = {
    {"wl_data_offer", 0, 2},
    {"wl_data_device", 0, 5},
    {"wl_data_device", 1, 3},
    {"wl_shell_surface", 0, 2},
    {"wl_shell_surface", 1, 3},
    {"wl_shell_surface", 2, 3},
    {"wl_shell_surface", 6, 3},
    {"wl_pointer", 0, 2}
};

// I don't think there will every be more than one sync waiting at once, but just in case handle up
// to 64 in a ring queue
#define NUM_SYNC_IDS 64

static struct {
    uint32_t timestamp;
    uint32_t serial_number;
    uint32_t surface_id; //TODO: Maybe could be multiple surfaces?
    uint32_t pointer_id;
    uint32_t keyboard_id;
    struct timespec last_msg_ts;
    struct timespec delay;
    uint32_t num_events;
    uint32_t event_idx;
    struct event* events;
    uint32_t had_first_damage;
    uint32_t displayed;
    uint32_t ready_for_input;
    uint32_t block_events;
    uint32_t buffer_width;
    uint32_t buffer_height;
    uint32_t sync_ids[NUM_SYNC_IDS];
    uint32_t sync_id_start;
    uint32_t sync_id_end;
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
    int serial;
    unsigned long millis;
    while (getline(&line, &len, fd) > 0) {
        struct event *event = &(fuzz.events[fuzz.num_events]);
        if (strncmp(line, "KEY", 3) == 0){
            event->type = KEY;
            sscanf(line + 4, "%d,%ld,%d,%d\n", &serial, &millis, &(event->key.key_code), &(event->key.pressed));
        }
        if (strncmp(line, "MOTION", 6) == 0) {
            event->type = MOUSE_MOVE;
            sscanf(line + 7, "%ld,%f,%f\n", &millis, &(event->mouse_move.x), &(event->mouse_move.y));
        }
        if (strncmp(line, "BUTTON", 6) == 0) {
            sscanf(line + 7, "%d,%ld,%d,%d\n", &serial, &millis, &(event->mouse_button.button_code), &(event->mouse_button.pressed));
            event->type = MOUSE_BUTTON;
        }
        if (strncmp(line, "ENTER", 5) == 0) {
            sscanf(line + 6, "%ld,%f,%f\n", &millis, &(event->mouse_enter.x), &(event->mouse_enter.y));
            event->type = MOUSE_ENTER;
        }
        if (strncmp(line, "LEAVE", 5) == 0) {
            sscanf(line + 6, "%ld\n", &millis);
            event->type = MOUSE_LEAVE;
        }

        event->delay.tv_sec = millis/MILLIS_PER_SEC;
        event->delay.tv_nsec = (millis % MILLIS_PER_SEC) * NANOS_PER_MILLI;
        fuzz.num_events ++;
    }
    free(line);

    fclose(fd);
    pass->user_data = wldbg;
    return 0;
}

static int fuzz_in(void *user_data, struct wldbg_message *message) {
    struct wldbg* wldbg = user_data;
    struct wldbg_resolved_message rm;
    if (!wldbg_resolve_message(message, &rm)) {
        return PASS_NEXT;
    }

    uint32_t *buf = message->data;
    uint32_t opcode = buf[1] & 0xffff;

    if (INTERFACE_MATCHES("wl_keyboard")) {
        if (opcode == 2) {
            wldbg->flags.skip = 1;
            return PASS_STOP;
        }
        else if(opcode == 3){
            if (fuzz.block_events) {
                wldbg->flags.skip = 1;
                return PASS_STOP;
            }
        }
    }
    else if (INTERFACE_MATCHES("wl_pointer")) {
        if (fuzz.block_events) {
            wldbg->flags.skip = 1;
            return PASS_STOP;
        }
    }
    else if (buf[0] == fuzz.sync_ids[fuzz.sync_id_start]) {
        // callback from display sync
        // response is the server's current serial number
        if (fuzz.serial_number) {
            buf[2] = ++(fuzz.serial_number);
        }
        else {
            fuzz.serial_number = buf[2];
        }
        ++(fuzz.sync_id_start);
        fuzz.sync_id_start %= NUM_SYNC_IDS;
    }

    for (int i = 0; i < sizeof(server_serials)/sizeof(struct serial_message); ++i) {
        if (INTERFACE_MATCHES(server_serials[i].name)) {
            if (opcode == server_serials[i].opcode) {
                if (fuzz.serial_number) {
                    buf[server_serials[i].serial_index] = ++(fuzz.serial_number);
                }
                else {
                    fuzz.serial_number = buf[server_serials[i].serial_index];
                }
            }
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

    if (INTERFACE_MATCHES("wl_compositor")) {
        if (opcode == 0) {
            fuzz.surface_id = buf[2];
        }
    }
    else if (INTERFACE_MATCHES("wl_seat")) {
        if (opcode == 0) {
            fuzz.pointer_id = buf[2];
        }
        else if (opcode == 1) {
            fuzz.keyboard_id = buf[2];
        }
    }
    else if (INTERFACE_MATCHES("wl_surface")) {
        if (opcode == 2) {
            fuzz.had_first_damage = 1;
        }
        else if (opcode == 6 && fuzz.had_first_damage) {
            fuzz.displayed = 1;
        }
    }
    else if (INTERFACE_MATCHES("wl_shm_pool")) {
        fuzz.buffer_width = buf[4];
        fuzz.buffer_height = buf[5];
    }
    else if (INTERFACE_MATCHES("wl_display")) {
        if (opcode == 0) {
            fuzz.sync_ids[fuzz.sync_id_end++] = buf[2];
            fuzz.sync_id_end %= NUM_SYNC_IDS;
        }
    }

    if (!(fuzz.ready_for_input) && fuzz.pointer_id && fuzz.keyboard_id && fuzz.displayed) {
        fuzz.ready_for_input = 1;
        //wait 10 miliseconds to make sure everything is ready.
        clock_gettime(CLOCK_MONOTONIC, &(fuzz.last_msg_ts ));
        fuzz.delay.tv_nsec = 10 * NANOS_PER_MILLI;
    }

    for (int i = 0; i < sizeof(client_serials)/sizeof(struct serial_message); ++i) {
        if (INTERFACE_MATCHES(client_serials[i].name)) {
            if (opcode == client_serials[i].opcode) {
                if (fuzz.serial_number) {
                    buf[client_serials[i].serial_index] = ++(fuzz.serial_number);
                }
                else {
                    fuzz.serial_number = buf[client_serials[i].serial_index];
                }
            }
        }
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

static int wldbg_fuzz_send(struct wldbg_message *msg) {
    struct wl_connection *conn = msg->connection->client.connection;

    if (wl_connection_write(conn, msg->data, msg->size) < 0) {
        perror("Writing message to connection");
        return -1;
    }
    if (wl_connection_flush(conn) < 0) {
        perror("wl_connection_flush");
        return -1;
    }
    wldbg_message_print(msg);
    return 0;
}

static int wldbg_fuzz_send_keyboard(struct wldbg *wldbg, unsigned int key, unsigned char pressed) {
    struct wldbg_message send_message;
    uint32_t buffer[6];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.keyboard_id;
    buffer[1] = (size << 16) | 3;
    buffer[2] = ++(fuzz.serial_number);
    buffer[3] = 0;
    buffer[4] = key;
    buffer[5] = pressed;

    send_message.connection = wldbg->message.connection;
    send_message.data = buffer;
    send_message.size = size;
    send_message.from = SERVER;

    return wldbg_fuzz_send(&send_message);
}

static int wldbg_fuzz_send_button(struct wldbg *wldbg, unsigned int button, unsigned char pressed) {
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

    return wldbg_fuzz_send(&send_message);
}

static int wldbg_fuzz_end_pointer_frame(struct wldbg* wldbg) {
    struct wldbg_message send_message;
    uint32_t buffer[2];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 5;

    send_message.connection = wldbg->message.connection;
    send_message.data = buffer;
    send_message.size = size;
    send_message.from = SERVER;

    return wldbg_fuzz_send(&send_message);
}

static int wldbg_fuzz_pointer_enter(struct wldbg* wldbg, float x, float y) {
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

    return wldbg_fuzz_send(&send_message);
}

static int wldbg_fuzz_pointer_leave(struct wldbg* wldbg) {
    struct wldbg_message send_message;
    uint32_t buffer[4];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.pointer_id;
    buffer[1] = (size << 16) | 1;
    buffer[2] = ++(fuzz.serial_number);
    buffer[3] = fuzz.surface_id;

    send_message.connection = wldbg->message.connection;
    send_message.data = buffer;
    send_message.size = size;
    send_message.from = SERVER;

    return wldbg_fuzz_send(&send_message);
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

    return wldbg_fuzz_send(&send_message);
}

int wldbg_fuzz_send_next(struct wldbg *wldbg) {
    if (fuzz.ready_for_input && fuzz.event_idx < fuzz.num_events) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        //TODO: this comparison is still wrong
        if ((fuzz.delay.tv_sec + fuzz.last_msg_ts.tv_sec) > ts.tv_sec || (fuzz.delay.tv_nsec+fuzz.last_msg_ts.tv_nsec) > ts.tv_nsec) {
            return 0;
        }

        struct event* event = &(fuzz.events[fuzz.event_idx]);
        switch (event->type) {
            case KEY:
                uint32_t pressed = event->key.pressed;
                uint32_t key_code = event->key.key_code;
                if (wldbg_fuzz_send_keyboard(wldbg, key_code, pressed)) {
                    return -1;
                }
                break;
            case MOUSE_BUTTON:
                pressed = event->mouse_button.pressed;
                uint32_t button_code = event->mouse_button.button_code;
                if (wldbg_fuzz_send_button(wldbg, button_code, pressed)) {
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
            case MOUSE_LEAVE:
                if (wldbg_fuzz_pointer_leave(wldbg)) {
                    return -1;
                }
                if (wldbg_fuzz_end_pointer_frame(wldbg)) {
                    return -1;
                }
                break;
        }

        fuzz.event_idx ++;
        fuzz.delay = event->delay;

        clock_gettime(CLOCK_MONOTONIC, &(fuzz.last_msg_ts ));
    }
    return 0;
}
