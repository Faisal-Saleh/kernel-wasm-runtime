/**
 * @file wasm_kernel_entry.c
 * @author Faisal Abdelmonem (fts@alumni.cmu.edu)
 * @brief 
 * @version 0.1
 * @date 2025-02-05
 * 
 * @copyright Copyright (c) 2025
 */


#include <linux/init.h> /* Needed for the macros */ 
#include <linux/module.h> /* Needed by all modules */ 
#include <linux/printk.h> /* Needed for pr_info() */
#include <linux/kernel.h>
#include <linux/kprobes.h>

#include <linux/slab.h> /* Needed for memory management, e.g., kfree, kmalloc */

#include <linux/completion.h>
#include <linux/err.h> /* for IS_ERR() */
#include <linux/kthread.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/sched.h>

#include <linux/jhash.h>

#include <linux/string.h>
#include <linux/uaccess.h>


#include "source/wasm3.h"
#include "source/m3_env.h"

#include "source/m3_api_kernel.h"

#include "wasm_chardev.h"
#include "kernel_wasm_internals.h"

//Create two threads
// - input thread:  waiting for message from user space
struct task_struct* input_thread;

int comp;
wait_queue_head_t wq;

/**
 * @todo maybe more efficient to use RCU, but deeeep.
 * @brief we are using a spinlock because it would be very dangerous to
 *        use a mutex and then sleep in the middle of the kernel module.
 *        in addition to that whenever we spin we disable preemption and interrupts
 *        to guarantee that the critical section is not interrupted (danger).
 * 
 */
static spinlock_t probe_table_lock;

static struct kprobe_map_entry* lookup_kprobe_entry(const char* symbol) {
    u32 key = jhash(symbol, strlen(symbol), 0);
    struct kprobe_map_entry* entry;
    hash_for_each_possible(kprobe_map, entry, node, key) {
        if (!strcmp(entry->symbol_name, symbol))
            return entry;
    }
    return NULL;
}

/* Register a kprobe for the symbol if not already registered,
 * and add it to the global kprobe_map.
 */
static int add_kprobe_entry(const char* symbol) {
    int ret;
    u32 hash_key = jhash(symbol, strlen(symbol), 0);
    struct kprobe_map_entry* entry = lookup_kprobe_entry(symbol);
    if (entry) {
        entry->count++;
        pr_info("Kprobe for symbol '%s' already registered\n", symbol);
        return 0;
    }

    entry = kzalloc(sizeof(struct kprobe_map_entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    
    entry->count = 1; // we are creating the first one

    /* Copy the symbol into our persistent buffer */
    int len = strlen(symbol);
    strncpy(entry->symbol_name, symbol, len);
    entry->symbol_name[len] = '\0';
    
    entry->kp.symbol_name = entry->symbol_name;
    if (sign_hook(entry)) {
        pr_err("Failed to register kprobe for symbol %s, error: %d\n", symbol, ret);
        kfree(entry);
        return -1;
    }

    /* Add the entry to the hash table */
    hash_add(kprobe_map, &entry->node, hash_key);
    pr_info("Registered kprobe for symbol %s\n", symbol);
    return 0;
}

// Remove a kprobe entry from the map by symbol name and unregister the kprobe
static void remove_kprobe_entry(const char* symbol) {
    struct kprobe_map_entry* entry = lookup_kprobe_entry(symbol);
    if (entry->count == 1) {
        unregister_kprobe(&entry->kp);
        hash_del(&entry->node);
        kfree(entry);
        pr_info("Removed kprobe entry for symbol: %s\n", symbol);
    } else if (entry->count > 1) {
        entry->count--;
    } else {
        pr_err("Should never reach this case\n");
    }
}

static int add_probe_to_table(struct probe_entry* entry) {
    unsigned long flags;
    spin_lock_irqsave(&probe_table_lock, flags);
    for (int i = 0; i < MAX_PROBES; i++) {
        if (probe_table[i] == NULL) {
            probe_table[i] = entry;
            pr_info("Added probe entry for symbol %s\n", entry->symbol_name);
            spin_unlock_irqrestore(&probe_table_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&probe_table_lock, flags);
    pr_err("Probe table full!\n");
    return -ENOMEM;
}

void attach_function(const char* f_name, struct module_entry* mod) {
    // for now we are only supporting kprobes so we check directly for that.
    if (strncmp(f_name, KPROBE_HEADER, strlen(KPROBE_HEADER))) {
        return;
    }

    struct probe_entry* probe_entry = kzalloc(sizeof(struct probe_entry), GFP_KERNEL);
    if (!probe_entry) {
        pr_info("Failed to allocate memory for probe\n");
        return;
    }

    probe_entry->id = mod->id;

    const char* first_colon = strchr(f_name, ':');
    if (!first_colon) {
        kfree(probe_entry);
        return;
    }
    const char* second_colon = strchr(first_colon + 1, ':');
    if (!second_colon) {
        kfree(probe_entry);
        return;
    }

    // copy first part
    // for now we are only supporting kprobes so do nothing with this
    // size_t len1 = first_colon - f_name;
    // char probe_type[SPLIT_SIZE];
    // strncpy(probe_type, f_name, len1);
    // probe_type[len1] = '\0';
    
    // Copy second part
    size_t sym_len = second_colon - (first_colon + 1);
    strncpy(probe_entry->symbol_name, first_colon + 1, sym_len);
    
    // Copy third part (everything after the second colon)
    char position[SPLIT_SIZE];
    strcpy(position, second_colon + 1);
    
    if (!strlen(position)) {
        kfree(probe_entry);
        return;
    }
    
    if (!strcmp(position, INVOKED_PRE)) {
        int result = m3_FindFunction(&(probe_entry->wasm_pre_func), mod->runtime, f_name);
        if (result) {
            pr_info("wasm-kernel: Function not found: %s\n", result);
            kfree(probe_entry);
            return;
        }
    } else if (!strcmp(position, INVOKED_POST)) {
        int result = m3_FindFunction(&(probe_entry->wasm_post_func), mod->runtime, f_name);
        if (result) {
            pr_info("wasm-kernel: Function not found: %s\n", result);
            kfree(probe_entry);
            return;
        }
    } else {
        pr_info("neither pre nor post, should not reach this case\n");
        return;
    }

    // note that with this decision we "add" a symbol name for each probe entry (pre or post)
    if (add_kprobe_entry(probe_entry->symbol_name)) {
        pr_info("could not add %s to the kprbe_map\n", probe_entry->symbol_name);
        kfree(probe_entry);
        return;
    }

    if (add_probe_to_table(probe_entry)) {
        remove_kprobe_entry(probe_entry->symbol_name);
        kfree(probe_entry);
        pr_info("could not add probe %s:%s to the probe table\n", probe_entry->symbol_name, position);
        return;
    }

    probe_entry->owner = mod;

    pr_info("the probe is %s\n", probe_entry->symbol_name);
    pr_info("the position is %s\n", position);
}

int search_exports(struct module_entry* module) {
    // Search exports
    pr_info("the number of exports is %d\n", module->module->numFunctions);
    for (u32 i = 0; i < module->module->numFunctions; i++) {
        const char* f_name = m3_GetFunctionName(Module_GetFunction(module->module, i));
        pr_info("the function found is %s\n", f_name);
        
        if (!strcmp(f_name, INVOKED_REPORT)) {
            int result = m3_FindFunction(&(module->wasm_report_func), module->runtime, f_name);
            if (result) {
                pr_info("wasm-kernel: Function not found: %s\n", result);
            }
            continue;
        }
        
        attach_function(f_name, module);
    }

    return 0;
}

static int setup_wasm(void) {
    M3Result result = m3Err_none;
    struct module_entry* mod = kzalloc(sizeof(struct module_entry), GFP_KERNEL);
    if (!mod) {
        pr_info("Failed to allocate memory for module entry\n");
        return -ENOMEM;
    }

    mod->env = m3_NewEnvironment();
    mod->runtime = m3_NewRuntime(mod->env, 64 * 1024, NULL);

    pr_info("wasm-kernel: Setting up the wasm runtime\n");
    mod->id = get_cur_id();
    
    pr_info("wasm-kernel: the binary size is: %d\n", get_binary_size(mod->id));
    // Load Wasm binary
    result = m3_ParseModule(mod->env, &(mod->module), get_binary(mod->id), get_binary_size(mod->id));
    if (result) {
        pr_info("wasm-kernel: Wasm module parse failed: %s\n", result);
        kfree(mod);
        return -1;
    }
    
    pr_info("wasm-kernel: parsed the module\n");
    // Load module
    result = m3_LoadModule(mod->runtime, mod->module);
    if (result) {
        pr_info("wasm-kernel: Wasm module load failed: %s\n", result);
        kfree(mod);
        return -1;
    }
    
    result = search_exports(mod);
    if (result) {
        pr_info("wasm-kernel: Could not register the kprobe\n", result);
        // I need to free all the probe_entries and kprobe_maps created in this step
        kfree(mod);
        return -1;
    }
    
    for (int i = 0; i < MAX_MODULES; i++) {
        if (module_entries[i] == NULL) {
            module_entries[i] = mod;
            pr_info("wasm-kernel: Wasm runtime setup successfully!\n");
            return 0;
        }
    }

    pr_info("mod table is full\n");
    kfree(mod);
    return -1;
}


static int wasm_call(struct pt_regs* regs, struct module_entry* m_entry, IM3Function wasm_fun) {
    // Get offset global
    IM3TaggedValue offset, size;
    offset = kmalloc(sizeof(struct M3TaggedValue), GFP_KERNEL);
    size   = kmalloc(sizeof(struct M3TaggedValue), GFP_KERNEL);

    if (!offset || !size) {
        pr_err("Failed to allocate memory for tagged values\n");
        return -ENOMEM;
    }
    
    IM3Global offset_global = m3_FindGlobal(m_entry->module, "buffer");
    pr_info("accessing the buffer size\n");
    m3_GetGlobal(offset_global, offset);
    
    IM3Global size_global = m3_FindGlobal(m_entry->module, "buffer_size");
    m3_GetGlobal(size_global, size);
    
    pr_info("accessing the wasm memory\n");
    uint8_t* wasm_mem = m3_GetMemory(m_entry->runtime, NULL, 0);
    if (!wasm_mem) {
        pr_info("wasm-kernel: failed to get wasm memory\n");
        return -ENOMEM;
    }

    pr_info("got the memory and passing the arguments now\n");
    
    struct pt_regs* syscall_regs = regs->di;
    const char __user *user_str = (const char __user*)syscall_regs->di;
    
    copy_from_user(wasm_mem + offset->value.i64, user_str, size->value.i32);
    
    pr_info("wasm-kernel: The types are %d, and %d\n", offset->type, size->type);

    M3Result result = m3_CallV(wasm_fun, offset->value.i32, syscall_regs->si);
    if (result) {
        pr_info("wasm-kernel: Function call failed: %s\n", result);
        return -1;
    }

    return 0;

}

/**
 * @note This can be optimized further in the future by using the hash map
 *       implementation provided in this file.
 *       In the future we also want to consider the possibility jumping directly
 *       to the wasm function, much faster and low overhead.
 * 
 * @param p 
 * @param regs 
 * @return int 
 */
static int pre_handler(struct kprobe* p, struct pt_regs* regs) {
    M3Result result = m3Err_none;
    
    int failed = -1;
    unsigned long flags;
    spin_lock_irqsave(&probe_table_lock, flags);
    for (int i = 0; i < MAX_PROBES; i++) {
        if (!probe_table[i] || !probe_table[i]->wasm_pre_func) continue;
        // pr_info("comparing %s with %s\n", p->symbol_name, probe_table[i]->symbol_name);
        if (!strcmp(p->symbol_name, probe_table[i]->symbol_name)) {
            if (!is_active(probe_table[i]->id)) { // found a probe
                failed = 0;
                continue;
            }

            pr_info("probe_table[%d] = %p, owner = %p, module = %p\n",
                    i,
                    probe_table[i],
                    probe_table[i] ? probe_table[i]->owner : NULL,
                    probe_table[i] && probe_table[i]->owner ? probe_table[i]->owner->module : NULL);

            int res = wasm_call(regs, probe_table[i]->owner, probe_table[i]->wasm_pre_func); 
            if (res == -ENOMEM) {
                spin_unlock_irqrestore(&probe_table_lock, flags);
                return -1;
            }
            if (res < 0) {
                continue;
            }
            
            pr_info("wasm-kernel: Wasm function executed successfully before kprobe!\n");
            failed = 0; // executed one wasm function successfully
        }
    }
    
    spin_unlock_irqrestore(&probe_table_lock, flags);
    if (failed) {
        pr_info("Pre: No probe found, should be unregistered(?)\n");
    }
    return failed;
}

static void post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags) {
    M3Result result = m3Err_none;
    
    unsigned long irq_flags;
    spin_lock_irqsave(&probe_table_lock, irq_flags);
    for (int i = 0; i < MAX_PROBES; i++) {
        if (!probe_table[i] || !probe_table[i]->wasm_post_func) continue;
        if (!strcmp(p->symbol_name, probe_table[i]->symbol_name)) {
            if (!is_active(probe_table[i]->id)) continue; // maybe another module has the symbol name active(?)
            
            uint8_t* wasm_mem = m3_GetMemory(probe_table[i]->owner->runtime, NULL, 0);
            if (!wasm_mem) {
                pr_info("wasm-kernel: failed to get wasm memory\n");
                spin_unlock_irqrestore(&probe_table_lock, irq_flags);
                return;
            }
            
            memcpy(wasm_mem, regs->di, sizeof(struct pt_regs));
            
            result = m3_CallV(probe_table[i]->wasm_post_func);
            if (result) {
                pr_info("wasm-kernel: Function call failed: %s\n", result);
                continue;
            }
            
            pr_info("wasm-kernel: Wasm function executed successfully after kprobe!\n");
            continue;
        }
    }
    spin_unlock_irqrestore(&probe_table_lock, irq_flags);
    pr_info("Post: No probe found, should be unregistered(?)\n");
}

static void report() {
    M3Result result = m3Err_none;
    int id = get_cur_id();

    pr_info("made it to the report call\n");
    
    for (int i = 0; i < MAX_MODULES; i++) {
        if (module_entries[i] == NULL) continue;
        if (id == module_entries[i]->id) {
            result = m3_CallV(module_entries[i]->wasm_report_func);
            char buffer[REPORT_BUFFER_SIZE];
            if (result) {
                snprintf(buffer, REPORT_BUFFER_SIZE, "Function call failed: %s\n", result);
                set_message(buffer);
                return;
            }
            
            int ret_count = 1; // can get in the future from module_entries[i]->wasm_report_func->funcType->numRets
            static uint64_t    valbuff[128]; // can get from wasm_report_func->numRetSlots
            static const void* valptrs[128];
            
            memset(valbuff, 0, sizeof(valbuff));
            for (int i = 0; i < ret_count; i++) {
                valptrs[i] = &valbuff[i];
            }
        
            result = m3_GetResults(module_entries[i]->wasm_report_func, ret_count, valptrs);
            if (result) return;
            
            uint32_t offset = *(uint32_t*)valptrs[0];
            uint8_t* wasm_mem = m3_GetMemory(module_entries[i]->runtime, NULL, 0);
            snprintf(buffer, REPORT_BUFFER_SIZE, "%s", &wasm_mem[offset]);
            // snprintf(buffer, REPORT_BUFFER_SIZE, "The probed function was called %d times\n", result_val);
            set_message(buffer);
            pr_info("wasm-kernel: returning successfully from report with %d\n", strlen(buffer));
        }
    }
    pr_info("Report: No probe found, should be unregistered(?)\n");
}


static int sign_hook(struct kprobe_map_entry* probe_entry) {
    int ret = 0;

    probe_entry->kp.pre_handler = pre_handler;
    probe_entry->kp.post_handler = post_handler;
    
    ret = register_kprobe(&probe_entry->kp);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kprobe for sys_call\n%d", ret);
        return ret;
    }
    
    pr_info("wasm-kernel: Kprobe registered successfully for syscall\n");
    return ret;
}

static int wasm_input_thread(void *arg) {
    M3Result result = m3Err_none;
    
    while(!kthread_should_stop()) {
        pr_info("wasm-kernel: Wating for wasm input to interpret\n");
        wait_event(wq, comp != WAITING);
        if(kthread_should_stop()) {
            pr_info("Exiting input thread!\n");
            break;
        }
        
        if (comp == REPORT) {
            report();
            comp = WAITING;
            wake_up(&wq);
            continue;
        }

        if (comp != INPUT) {
            comp = WAITING;
            continue;
        }

        pr_info("wasm-kernel: Found the wasm input\n");
         
        // only one at a time so no synchronization needed.
        int ret = setup_wasm();
        if (ret) {
            pr_info("wasm-kernel: Failed to Setup Wasm, returned %d\n", ret);
            return ret;    
        }

        comp = WAITING;
        pr_info("wasm-kernel: kprobes hooked successfully\n");
    }
    
    return 0;
}

static int __init wasm_module_init(void) {
    pr_info("wasm-kernel: Initializing wasm kernel module\n");

    int ret = chardev_init();
    if (ret) {
        pr_info("wasm-kernel: char device init error!\n");
        return ret;
    }

    spin_lock_init(&probe_table_lock);

    init_waitqueue_head(&wq);
    comp = WAITING;

    input_thread = kthread_create(wasm_input_thread, NULL, "Input thread");
    if (IS_ERR(input_thread)) {
        pr_info("wasm-kernel: Input thread error!\n");
        return PTR_ERR(input_thread);
    }

    wake_up_process(input_thread);

    return 0;
}


static void __exit wasm_module_exit(void) {
    pr_info("wasm-kernel: cleaning up...\n");

    chardev_exit();
    comp = STOP;
    kthread_stop(input_thread);
    // wake_up(&wq);

    for (int i = 0; i < MAX_MODULES; i++) {
        if (module_entries[i]) {
            pr_info("Freeing module entry id: %d\n", module_entries[i]->id);
            m3_FreeRuntime(module_entries[i]->runtime);
            m3_FreeEnvironment(module_entries[i]->env);
            kfree(module_entries[i]);
            module_entries[i] = NULL;
        }
    }

    for (int i = 0; i < MAX_PROBES; i++) {
        if (probe_table[i]) {
            pr_info("Unregistering kprobe for symbol: %s\n", probe_table[i]->symbol_name);
            remove_kprobe_entry(probe_table[i]->symbol_name);
            kfree(probe_table[i]);
            probe_table[i] = NULL;
        }
    }
    pr_info("wasm-kernel: Exiting Wasm Kernel Module\n");
}

module_init(wasm_module_init);
module_exit(wasm_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Faisal Abdelmonem");
MODULE_DESCRIPTION("Kernel module executing probed custom code with Wasm3");