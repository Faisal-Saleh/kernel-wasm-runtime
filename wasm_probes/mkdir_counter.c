int counter = 0;
char buffer[128];

__attribute__((export_name("kprobe:__x64_sys_mkdir:pre")))
void pre() {
    counter++;
}

void format_report(char *buffer, int count) {
    // Write the static prefix
    const char *prefix = "mkdir was called ";
    const char *suffix = " times\n";

    char *ptr = buffer;

    // Copy prefix
    while (*prefix) *ptr++ = *prefix++;

    // Convert integer to string
    if (count == 0) {
        *ptr++ = '0';
    } else {
        char numbuf[12];
        int i = 0;
        while (count > 0 && i < sizeof(numbuf) - 1) {
            numbuf[i++] = '0' + (count % 10);
            count /= 10;
        }
        // Reverse and write digits
        while (--i >= 0) {
            *ptr++ = numbuf[i];
        }
    }

    // Copy suffix
    while (*suffix) *ptr++ = *suffix++;

    *ptr = '\0';  // null-terminate
}


char* report() {
    format_report(buffer, counter);
    return buffer;
}