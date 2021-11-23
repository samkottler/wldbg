#include <stdio.h>
#include <time.h>
#include <linux/input-event-codes.h>

#include "wldbg-private.h"
#include "wldbg-pass.h"
#include "passes.h"
#include "wldbg-parse-message.h"
#include "wayland/wayland-util.h"
#include "wayland/wayland-private.h"

#define MILLIS_PER_SEC  1000
#define NANOS_PER_MILLI 1000000
#define NANOS_PER_SEC   1000000000

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

static uint32_t keys[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98,
    99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
    118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136,
    137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155,
    156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174,
    175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193,
    194, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217,
    218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236,
    237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 352, 353, 354, 355, 356, 357, 358,
    359, 360, 361, 362, 363, 364, 365, 366, 367, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377,
    378, 379, 380, 381, 382, 383, 384, 385, 386, 387, 388, 389, 390, 391, 392, 393, 394, 395, 396,
    397, 398, 399, 400, 401, 402, 403, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415,
    416, 417, 418, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 431, 432, 433, 434,
    435, 436, 437, 438, 439, 440, 441, 442, 444, 445, 446, 448, 449, 450, 451, 464, 465, 466, 467,
    468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 497,
    498, 499, 500, 501, 502, 503, 504, 505, 506, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521,
    522, 523, 524, 525, 526, 527, 528, 529, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540,
    541, 542, 560, 561, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 592, 593, 608, 609, 610,
    611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 622, 623, 624, 625, 626, 627, 628, 629,
    630, 631, 632, 633, 634, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669,
    670, 671, 672, 673, 674, 675, 676, 677, 678, 679, 680, 681, 682, 683, 684, 685, 688, 689, 690,
    691, 692, 693, 696, 697, 698, 699, 700, 767
};
static uint32_t buttons[] = {
    256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 272, 273, 274, 275, 276, 277, 278, 279, 288,
    289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 303, 304, 305, 306, 307, 308, 309, 310,
    311, 312, 313, 314, 315, 316, 317, 318, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
    331, 332, 333, 334, 335, 336, 337, 544, 545, 546, 547, 704, 705, 706, 707, 708, 709, 710, 711,
    712, 713, 714, 715, 716, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730,
    731, 732, 733, 734, 735, 736, 737, 738, 739, 740, 741, 742, 743
};

static struct {
    struct timespec timestamp_start;
    uint32_t serial_number;
    uint32_t surface_id; //TODO: Maybe could be multiple surfaces?
    uint32_t pointer_id;
    uint32_t keyboard_id;
    struct timespec last_msg_ts;
    struct timespec delay;
    struct event next_event;
    struct {
        unsigned char key_status[sizeof (keys)/sizeof(*keys)];
        unsigned char button_status[sizeof (buttons)/sizeof(*buttons)];
        unsigned char mouse_entered;
    } events;
    uint32_t delay_min;
    uint32_t delay_max;
    uint32_t had_first_damage;
    uint32_t displayed;
    uint32_t ready_for_input;
    uint32_t block_events;
    uint32_t buffer_width;
    uint32_t buffer_height;
    uint32_t sync_ids[NUM_SYNC_IDS];
    uint32_t sync_id_start;
    uint32_t sync_id_end;
    uint32_t frame_id;
    uint32_t verbose;
    char* program_name;
    struct wldbg_connection *conn;
} fuzz;

static void print_usage(void *user_data) {
    printf("Perform fuzz testing\n"
           "\n"
           "Usage: wldbg fuzz [options] <seed> ...\n"
           "\n"
           "Available options:\n"
           "    block           -- prevent real keyboard and mouse events from being sent\n"
           "    help            -- print this message\n"
           "    verbose         -- print messages generated by fuzzer as they are sent\n"
           "    program=<name>  -- only send messages to connections with client program matching name\n"
           "    delay_min=<min> -- minimum delay between events in milliseconds (default 10)\n"
           "    delay_max=<max> -- maximum delay between events in milliseconds (default 1000)\n"
    );
}

// string hash function djb2 developed by dan bernstein
static unsigned long hash(const char* str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *(str++))) {
        hash = ((hash << 5) + hash) ^ c; /* (hash * 33) ^ c */
    }

    return hash;
}

static void generate_consistent_event() {
    unsigned long millis = (rand() % (fuzz.delay_max - fuzz.delay_min)) + fuzz.delay_min;
    fuzz.next_event.delay.tv_nsec = (millis % MILLIS_PER_SEC) * NANOS_PER_MILLI;
    fuzz.next_event.delay.tv_sec = millis / MILLIS_PER_SEC;
    int number_events = fuzz.events.mouse_entered ? 4 : 2;
    switch (rand()%number_events) {
        case 0:
            fuzz.next_event.type = KEY;
            uint32_t key_idx = rand() % sizeof(keys)/sizeof(*keys);
            fuzz.next_event.key.key_code = keys[key_idx];
            fuzz.events.key_status[key_idx] = 1 - fuzz.events.key_status[key_idx];
            fuzz.next_event.key.pressed = fuzz.events.key_status[key_idx];
            break;
        case 1:
            if (fuzz.events.mouse_entered) {
                fuzz.next_event.type = MOUSE_LEAVE;
            }
            else {
                fuzz.next_event.type = MOUSE_ENTER;
                fuzz.next_event.mouse_enter.x = ((float)rand()) / (float)RAND_MAX;
                fuzz.next_event.mouse_enter.y = ((float)rand()) / (float)RAND_MAX;
            }
            fuzz.events.mouse_entered = 1 - fuzz.events.mouse_entered;
            break;
        case 2:
            fuzz.next_event.type = MOUSE_MOVE;
            fuzz.next_event.mouse_move.x = ((float)rand()) / (float)RAND_MAX;
            fuzz.next_event.mouse_move.y = ((float)rand()) / (float)RAND_MAX;
            break;
        case 3:
            fuzz.next_event.type = MOUSE_BUTTON;
            uint32_t button_idx = rand() % sizeof(buttons)/sizeof(*buttons);
            fuzz.next_event.mouse_button.button_code = buttons[button_idx];
            fuzz.events.button_status[button_idx] = 1 - fuzz.events.button_status[button_idx];
            fuzz.next_event.mouse_button.pressed = fuzz.events.button_status[button_idx];
            break;
    }

}

static int fuzz_init(struct wldbg *wldbg, struct wldbg_pass *pass, int argc, const char *argv[]) {
    if (argc < 2) {
        printf("fuzzer needs a random seed\n");
        return -1;
    }
    wldbg->flags.fuzz_mode = 1;

    memset(&fuzz, 0, sizeof(fuzz));

    fuzz.delay_min = 10;
    fuzz.delay_max = 1000;

    for (int i = 1; i < argc - 1; ++i) {
        if (strcmp(argv[i], "block") == 0) {
            fuzz.block_events = 1;
        }
        else if (strcmp(argv[i], "help") == 0) {
            print_usage(NULL);
            wldbg_exit(wldbg);
            return 0;
        }
        else if (strcmp(argv[i], "verbose") == 0) {
            fuzz.verbose = 1;
        }
        else if (strncmp(argv[i], "program=", 8) == 0) {
            fuzz.program_name = strdup(argv[i]+8);
        }
        else if (strncmp(argv[i], "delay_min=", 10) == 0) {
            fuzz.delay_min = atoi(argv[i] + 10);
        }
        else if (strncmp(argv[i], "delay_max=", 10) == 0) {
            fuzz.delay_max = atoi(argv[i] + 10);
        }
        else {
            printf("invalid option: %s\n", argv[i]);
            wldbg_exit(wldbg);
        }
    }

    unsigned int seed = hash(argv[argc-1]) & 0xffffffff;
    srand(seed);

    generate_consistent_event();

    pass->user_data = wldbg;
    return 0;
}

static int fuzz_in(void *user_data, struct wldbg_message *message) {
    struct wldbg* wldbg = user_data;
    struct wldbg_resolved_message rm;
    if (!wldbg_resolve_message(message, &rm)) {
        return PASS_NEXT;
    }

    if (fuzz.program_name) {
        if (strcmp(message->connection->client.program, fuzz.program_name) == 0) {
            fuzz.conn = message->connection;
        }
    }
    else {
        fuzz.conn = message->connection;
    }

    if (message->connection != fuzz.conn) {
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
    else if (buf[0] == fuzz.frame_id && fuzz.frame_id != 0) {
        fuzz.frame_id = 0;
        clock_gettime(CLOCK_MONOTONIC, &(fuzz.timestamp_start));
        long millis = buf[2];
        long nanos = (millis % MILLIS_PER_SEC) * NANOS_PER_MILLI;
        long secs = millis / MILLIS_PER_SEC;
        if (nanos > fuzz.timestamp_start.tv_nsec) {
            fuzz.timestamp_start.tv_nsec += NANOS_PER_SEC;
            fuzz.timestamp_start.tv_sec -= 1;
        }
        fuzz.timestamp_start.tv_nsec -= nanos;
        fuzz.timestamp_start.tv_sec -= secs;
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

    if (fuzz.program_name) {
        if (strcmp(message->connection->client.program, fuzz.program_name) == 0) {
            fuzz.conn = message->connection;
        }
    }
    else {
        fuzz.conn = message->connection;
    }

    if (message->connection != fuzz.conn) {
        return PASS_NEXT;
    }

    uint32_t *buf = message->data;
    uint32_t opcode = buf[1] & 0xffff;

    if (INTERFACE_MATCHES("wl_compositor")) {
        if (opcode == 0 && fuzz.surface_id == 0) {
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
        else if (opcode == 3) { // frame
            fuzz.frame_id = buf[2];
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

    if (!(fuzz.ready_for_input) && fuzz.pointer_id && fuzz.keyboard_id && fuzz.displayed && fuzz.conn) {
        fuzz.ready_for_input = 1;
        //wait 100 miliseconds to make sure everything is ready.
        clock_gettime(CLOCK_MONOTONIC, &(fuzz.last_msg_ts ));
        fuzz.delay.tv_nsec = 100 * NANOS_PER_MILLI;
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
    if (fuzz.program_name) {
        free(fuzz.program_name);
    }
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
    pass->wldbg_pass.help = print_usage;
    pass->wldbg_pass.description = "Pass to help keep track of info for fuzz testing";

    return pass;
}

static int wldbg_fuzz_send(struct wldbg_message *msg) {
    msg->connection = fuzz.conn;
    struct wl_connection *conn = msg->connection->client.connection;

    if (wl_connection_write(conn, msg->data, msg->size) < 0) {
        perror("Writing message to connection");
        return -1;
    }
    if (wl_connection_flush(conn) < 0) {
        perror("wl_connection_flush");
        return -1;
    }
    if (fuzz.verbose) {
        wldbg_message_print(msg);
    }
    return 0;
}

static uint32_t get_timestamp() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    // compute millis in ts - fuzz.timestamp_start
    long nanos, secs;

    if (ts.tv_nsec < fuzz.timestamp_start.tv_nsec) {
        ts.tv_nsec += NANOS_PER_SEC;
        ts.tv_sec -= 1;
    }

    nanos = ts.tv_nsec - fuzz.timestamp_start.tv_nsec;
    secs = ts.tv_sec - fuzz.timestamp_start.tv_sec;

    return (secs * MILLIS_PER_SEC) + (nanos / NANOS_PER_MILLI);

}

static int wldbg_fuzz_send_keyboard(struct wldbg *wldbg, unsigned int key, unsigned char pressed) {
    struct wldbg_message send_message;
    uint32_t buffer[6];
    uint32_t size = sizeof(buffer);
    buffer[0] = fuzz.keyboard_id;
    buffer[1] = (size << 16) | 3;
    buffer[2] = ++(fuzz.serial_number);
    buffer[3] = get_timestamp();
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
    buffer[3] = get_timestamp();
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
    buffer[2] = get_timestamp();
    buffer[3] = real_x << 8;
    buffer[4] = real_y << 8;

    send_message.connection = wldbg->message.connection;
    send_message.data = buffer;
    send_message.size = size;
    send_message.from = SERVER;

    return wldbg_fuzz_send(&send_message);
}

int wldbg_fuzz_send_next(struct wldbg *wldbg) {
    if (fuzz.ready_for_input) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        //TODO: this comparison is still wrong
        if ((fuzz.delay.tv_sec + fuzz.last_msg_ts.tv_sec) > ts.tv_sec) {
            return 0;
        }
        else if ((fuzz.delay.tv_sec + fuzz.last_msg_ts.tv_sec) == ts.tv_sec){
            if ((fuzz.delay.tv_nsec + fuzz.last_msg_ts.tv_nsec) > ts.tv_nsec){
                return 0;
            }
        }

        struct event* event = &(fuzz.next_event);
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

        fuzz.delay = event->delay;
        generate_consistent_event();

        clock_gettime(CLOCK_MONOTONIC, &(fuzz.last_msg_ts ));
    }
    return 0;
}
