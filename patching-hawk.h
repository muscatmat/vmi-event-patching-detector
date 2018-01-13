#ifndef NAIVE_HAWK
#define NAIVE_HAWK

/////////////////////
// Structs
/////////////////////

struct event_data 
{
    // Event type
    pid_t pid;

    // Patched page address
    addr_t page_addr;
};



///////////////////// 
// Functions
/////////////////////

bool register_patched_processes(vmi_instance_t vmi, string dwarf_fp);
void register_patched_memory_page(vmi_instance_t vmi, vmi_pid_t pid, addr_t page_addr);
event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event);
event_response_t page_change_callback(vmi_instance_t vmi, vmi_event_t *event);

void cleanup(vmi_instance_t vmi);
void free_event_data(vmi_event_t *event, status_t rc);

void print_event(vmi_event_t *event);

void *security_checking_thread(void *arg);

#endif