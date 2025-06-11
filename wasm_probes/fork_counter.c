int counter = 0;

__attribute__((export_name("kprobe:__do_sys_vfork:pre")))
void pre() {
    counter++;
}

__attribute__((export_name("kprobe:__do_sys_vfork:post")))
void post() {}

int report() {
    return counter;
    printf("we are returning\n");
}