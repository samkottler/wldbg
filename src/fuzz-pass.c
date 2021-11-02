#include <stdio.h>

#include "wldbg-private.h"
#include "wldbg-pass.h"
#include "passes.h"
#include "wayland/wayland-util.h"

static int fuzz_init(struct wldbg *wldbg, struct wldbg_pass *pass, int argc, const char *argv[]) {
    printf("here\n");
    return 0;
}

static int fuzz_in(void *user_data, struct wldbg_message *message) {
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
