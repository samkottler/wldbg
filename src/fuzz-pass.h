#ifndef __FUZZ_PASS_H
#define __FUZZ_PASS_H

struct pass *create_fuzz_pass();

int wldbg_fuzz_send_next(struct wldbg* wldbg);

#endif
