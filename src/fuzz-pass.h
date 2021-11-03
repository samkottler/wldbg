#ifndef __FUZZ_PASS_H
#define __FUZZ_PASS_H

int wldbg_add_fuzz_pass(struct wldbg* wldbg);

int wldbg_fuzz_send_next(struct wldbg* wldbg);

#endif
