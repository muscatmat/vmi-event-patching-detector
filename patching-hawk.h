#ifndef NAIVE_HAWK
#define NAIVE_HAWK

/////////////////////
// Structs
/////////////////////

struct event_data 
{
    // Event type
    unsigned long type;

    // Physical address of event to monitor
    unsigned long physical_addr;

    // Size of monitoring page
    int monitor_size;
};

///////////////////// 
// Functions
/////////////////////

void register_patched_memory_page(vmi_instance_t vmi, vmi_pid_t pid, addr_t page_addr);
//bool register_patched_process_event(vmi_instance_t vmi, char *req_process);

void cleanup(vmi_instance_t vmi);

event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event);

void free_event_data(vmi_event_t *event, status_t rc);
void print_event(vmi_event_t *event);

void *security_checking_thread(void *arg);

#endif