/**
 * VMI Event Based Naive Approach Application
 **/
/////////////////////
// Includes
/////////////////////
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <Python.h>

#include <libvmi/libvmi.h> 
#include <libvmi/events.h>

#include <atomic>
#include <fstream>
#include <string>

using namespace std;

#include "naive-deque.h"
#include "naive-event-list.h"
#include "mmap-list.h"
#include "patching-hawk.h"
  
/////////////////////
// Defines
/////////////////////
#define UNUSED_PARAMETER(expr) (void)(expr);
//#define MYDEBUG
// #define printf(fmt, ...) (void)(0)

#define PAUSE_VM 0

#define BUFFER_GLOBAL_VAR_OFFSET 0x201800

// Event Names Contants
#define INTERRUPTED_EVENT 64
#define PUTS_EVENT 2
#define OPEN_EVENT 3
#define CLOSE_EVENT 4
#define FORK_EVENT 5
#define EXEC_EVENT 6

/////////////////////
// Global Variables
/////////////////////
Deque<int> event_deque;
struct vmi_event_node *vmi_event_head;
string dwarf_fp;
bool didFirstChange = false;

// Result Measurements
//#define MONITORING_MODE

//#define ANALYSIS_MODE
//#define RE_REGISTER_EVENTS

//#define MEASURE_EVENT_CALLBACK_TIME
#define ALWAYS_SEND_EVENT /* Always send event due to register multiple event on same page failure */

// Result variables
long irrelevant_events_count = 0;
long monitored_events_count = 0;

/////////////////////
// Static Functions
/////////////////////
static atomic<bool> interrupted(false);
static void close_handler(int sig)
{
    UNUSED_PARAMETER(sig); 
    interrupted = true;
    event_deque.push_front(INTERRUPTED_EVENT);
}

// Commented since function is unused but might be required in the future
// static int retrieve_struct_size(string file_path, string struct_name){
//     int result = -1;
//     ifstream in_file(file_path);

//     string struct_substr("<DW_TAG_structure_type> DW_AT_name<\"" + struct_name + "\">");
//     string struct_size_substr("DW_AT_byte_size<");
//     string line;
//     while (getline(in_file, line))
//     {
//         if (line.find(struct_substr) != string::npos){
//             string temp_mem_loc(line.substr(line.find(struct_size_substr) + struct_size_substr.size()));
//             result = stoi(temp_mem_loc.substr(0, temp_mem_loc.find(">")), NULL, 16);
//             break;
//         }
//     }

//     return result;
// }

static int retrieve_offset(string file_path, string struct_name, string member_name){
    int result = -1;
    ifstream in_file(file_path);

    string struct_substr("<DW_TAG_structure_type> DW_AT_name<\"" + struct_name + "\">");
    string member_substr("<DW_TAG_member> DW_AT_name<\"" + member_name + "\">");
    string member_loc_substr("DW_AT_data_member_location<");
    
    bool struct_found = false;
    string line;
    while (getline(in_file, line))
    {
        if (struct_found)
        {
            if (line.substr(1,1).compare("2") != 0){
                printf("Member: %s not found in struct: %s\n", member_name.c_str(), struct_name.c_str());
                break;
            }

            if (line.find(member_substr) != string::npos){
                string temp_mem_loc(line.substr(line.find(member_loc_substr) + member_loc_substr.size()));
                result = stoi(temp_mem_loc.substr(0, temp_mem_loc.size() - 1));
                break;
            }
        }

        if (line.find(struct_substr) != string::npos){
            struct_found = true;
            continue;
        }
    }

    return result;
}

int main(int argc, char **argv)
{
    clock_t program_time = clock();
    printf("Patching Event Hawk Program Initiated!\n");

    if(argc != 3)
    {
        fprintf(stderr, "Usage: patching-hawk <VM Name> <VM module.dwarf>\n");
        printf("Patching Event Hawk-Eye Program Ended!\n");
        return 1; 
    }

    // Setup module dwarf file
    dwarf_fp = string(argv[2]);

    // Initialise variables
    vmi_instance_t vmi;

    // Setup signal action handling
    struct sigaction act;
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    char *vm_name = argv[1];
    
    // Initialize the libvmi library.
    if (VMI_FAILURE ==
        vmi_init_complete(&vmi, vm_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, NULL, VMI_CONFIG_GLOBAL_FILE_ENTRY, NULL, NULL))
    {
        printf("Failed to init LibVMI library.\n");
        return 2;
    }
    printf("LibVMI initialise succeeded: %p\n", vmi);

    #ifdef MONITORING_MODE    
        // Start security checking thread
        pthread_t sec_thread;
        if (pthread_create(&sec_thread, NULL, security_checking_thread, (void *)vmi) != 0)
            printf("Failed to create thread");
    #endif

    if(PAUSE_VM == 1) 
    {
        // Pause vm for consistent memory access
        if (VMI_SUCCESS != vmi_pause_vm(vmi))
        {
            printf("Failed to pause VM\n");
            cleanup(vmi);
            return 3;
        }
    }

    register_patched_processes(vmi, dwarf_fp);

    printf("Waiting for events...\n");
    while (!interrupted)
    {
         if (vmi_events_listen(vmi, 500) != VMI_SUCCESS) {
            printf("Error waiting for events, quitting...\n");
            interrupted = -1;
        }
    }

    cleanup(vmi);

    printf("Patching Event Hawk-Eye Program Ended!\n");
    program_time = clock() - program_time;
    printf("Execution time: %f seconds\n", ((double)program_time)/CLOCKS_PER_SEC);
    return 0;
}

/////////////////////
// Definitions
/////////////////////
event_response_t mem_write_cb(vmi_instance_t vmi, vmi_event_t *event) 
{ 
    #ifdef MEASURE_EVENT_CALLBACK_TIME
        clock_t t;
        t = clock();
    #endif

    print_event(event);

    monitored_events_count++;
    vmi_clear_event(vmi, event, NULL);

    // Validate written data is from patched page
    addr_t event_addr = (event->mem_event.gfn << 12) + event->mem_event.offset;
    uint32_t event_page_data;
    vmi_read_32_pa(vmi, event_addr, &event_page_data);

    if (event->mem_event.offset != 0 || (event_page_data != 0 && didFirstChange)){
        printf("Offset \%" PRIx64" is invalid or data %d is not zero!\n",event->mem_event.offset, event_page_data);
        // MM - TODO: Check for process existince and return
        return VMI_EVENT_RESPONSE_NONE;
    }

    didFirstChange = true;

    vmi_step_event(vmi, event, event->vcpu_id, 1, page_change_callback);

    #ifdef MEASURE_EVENT_CALLBACK_TIME
        t = clock() - t;
        printf("mem_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
    #endif

    return VMI_EVENT_RESPONSE_NONE;
} 

event_response_t page_change_callback(vmi_instance_t vmi, vmi_event_t *event)
{
    // Read event page information
    addr_t event_addr = (event->mem_event.gfn << 12) + event->mem_event.offset;
    uint32_t event_type;
    vmi_read_32_pa(vmi, event_addr, &event_type);

    printf("Event Type is %d\n", event_type);

    #ifdef MONITORING_MODE
        // MM - TODO: Check event_type is within accepted range and whether to register event SIGNATURE??
        event_deque.push_back(event_type);
    #endif

    // MM - Rewrite zero again for page data validation
    uint32_t zero_data = 0;
    vmi_write_32_pa(vmi, event_addr, &zero_data);

    if (vmi_register_event(vmi, event) == VMI_FAILURE)
    {
        printf("Failed to register event in callback.\n");

        interrupted = -1;
        
        return VMI_EVENT_RESPONSE_NONE;
    }

    return VMI_EVENT_RESPONSE_NONE;
}


void free_event_data(vmi_event_t *event, status_t rc)
{
    struct event_data * data = (struct event_data *) event->data;
    printf("Freeing data for patched page: \%" PRIx64" due to status %d \n", data->page_addr, rc);
    free(data); 
}

bool register_patched_processes(vmi_instance_t vmi, string dwarf_fp)
{
    unsigned long tasks_offset = vmi_get_offset(vmi, "linux_tasks");
    // unsigned long name_offset = vmi_get_offset(vmi, "linux_name");
    unsigned long pid_offset = vmi_get_offset(vmi, "linux_pid");

    unsigned long mm_offset = retrieve_offset(dwarf_fp, "task_struct", "mm");

    unsigned long mmap_offset = retrieve_offset(dwarf_fp, "mm_struct", "mmap");

    unsigned long map_start_offset = retrieve_offset(dwarf_fp, "vm_area_struct", "vm_start");
    unsigned long map_end_offset = retrieve_offset(dwarf_fp, "vm_area_struct", "vm_end");
    unsigned long map_next_offset = retrieve_offset(dwarf_fp, "vm_area_struct", "vm_next");

    addr_t list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;

    addr_t next_list_entry = list_head;

    // Perform task list walk-through
    addr_t current_process = 0;
    vmi_pid_t pid = 0;
    status_t status;

    do 
    {
        current_process = next_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        // MM - IMP: DO NOT USE vmi_pagetable_lookup_extended AS IT BREAKS LIBVMI
        // page_info_t page_info;
        // status = vmi_pagetable_lookup_extended(vmi, vmi_pid_to_dtb(vmi, pid), current_process, &page_info);
        // if (status == VMI_FAILURE)
        // {
        //     printf("Failed to retrieve page info at %" PRIx64"\n", current_process);
        //     return false;
        // }
        // printf("Page Size: %d\n", page_info.size);
        
        // Retrieve process maps
        addr_t current_mm;
        addr_t current_mmap;

        uint64_t mmap_start;
        uint64_t mmap_end;

        vmi_read_addr_va(vmi, current_process + mm_offset, 0, (addr_t*)&current_mm);
        vmi_read_addr_va(vmi, current_mm + mmap_offset, 0, (addr_t*)&current_mmap);

        addr_t mypage_buffer = 0;

        struct mmap_data *mmap_head = NULL;
        struct mmap_data *cursor = NULL;

        while (current_mmap != 0) 
        {
            vmi_read_64_va(vmi, current_mmap + map_start_offset, 0, (uint64_t*)&mmap_start);
            vmi_read_64_va(vmi, current_mmap + map_end_offset, 0, (uint64_t*)&mmap_end);

            vmi_read_addr_va(vmi, mmap_start + BUFFER_GLOBAL_VAR_OFFSET, pid, (addr_t*)&mypage_buffer);

            struct mmap_data *mmap_node = (struct mmap_data *) malloc(sizeof(struct mmap_data));
            mmap_node->map_start = mmap_start;
            mmap_node->buffer_addr = mypage_buffer;
            mmap_node->next = NULL;

            if (mmap_head == NULL)
            {   
                mmap_head = mmap_node;
                cursor = mmap_head;
            }
            else
            {
                cursor->next = mmap_node;
                cursor = cursor->next;
            }

            vmi_read_addr_va(vmi, current_mmap + map_next_offset, 0, (addr_t*)&current_mmap);
        }

        // Search for process patched page
        cursor = mmap_head;
        while(cursor != NULL)
        {
            if (cursor->buffer_addr != 0)
            {
                if (search_mmap_for_buffer(mmap_head, cursor->buffer_addr) != NULL)
                {
                    // Register patch process page
                    register_patched_memory_page(vmi, pid, cursor->buffer_addr);
                    break;
                }
            }
            cursor = cursor->next;
        }

        // Free mmap data list
        while (mmap_head != NULL) 
        {
            cursor = mmap_head;
            mmap_head = mmap_head->next;

            free(cursor);
        }
       
        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE)
        {
            printf("Failed to read next pointer in loop at %" PRIx64"\n", next_list_entry);
            return false;
        }
    } while(next_list_entry != list_head);

    return true;
}

void register_patched_memory_page(vmi_instance_t vmi, vmi_pid_t pid, addr_t page_addr) 
{           
    if (page_addr == 0){
        printf("Pid: %d has page_addr set as 0\n", pid);
        return;
    }

    printf("Registering event for pid: %d and addr: %" PRIx64"\n", pid, page_addr);
    addr_t struct_addr = vmi_translate_uv2p(vmi, page_addr, pid);
    
    if (struct_addr == 0){
        printf("Physical address could not be retrieved: %" PRIx64"\n", struct_addr);
        return;
    }

    printf("Registering event for physical addr: %" PRIx64"\n", struct_addr);
    // Register write memory event (>> 12 to point to page base)
    vmi_event_t *patch_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
    SETUP_MEM_EVENT(patch_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);

    struct event_data *event_data = (struct event_data *) malloc(sizeof(struct event_data));
    event_data->pid = pid;
    event_data->page_addr = page_addr;

    patch_event->data = event_data;

    if (vmi_register_event(vmi, patch_event) == VMI_FAILURE)
    {
        printf("Failed to register event.\n");

        cleanup(vmi);
        printf("Patching Event Hawk-Eye Program Ended!\n");
        return;
    }
}

void cleanup(vmi_instance_t vmi)
{
    // Send Interrupt event to security checking thread
    interrupted = true;
    event_deque.push_front(INTERRUPTED_EVENT);

    if(PAUSE_VM == 1) 
        vmi_resume_vm(vmi);

    struct vmi_event_node *current = vmi_event_head;
    struct vmi_event_node *next = vmi_event_head;

    while (current) 
    {
        next = current->next;

        vmi_clear_event(vmi, current->event, free_event_data);

        free(current);
        current = next;
    }

    // Perform cleanup of libvmi instance
    vmi_destroy(vmi);

    // Print Statistics
    if (monitored_events_count != 0) 
    {
        printf("Total Irrelevant Events: %ld\n", irrelevant_events_count);
        printf("Total Hit Events: %ld\n", (monitored_events_count - irrelevant_events_count));
        printf("Total Monitored Events: %ld\n", monitored_events_count);
        printf("Total Irrelevant Events Percentage: %f%%\n", (double) irrelevant_events_count / (double)monitored_events_count * 100);
        printf("Total Hit Events: %f%%\n", (1 - (double) irrelevant_events_count / (double)monitored_events_count) * 100);
    }
}

void print_event(vmi_event_t *event)
{
    printf("PAGE ACCESS: %c%c%c for GFN %" PRIx64" (offset %06" PRIx64") gla %016" PRIx64" (vcpu %" PRIu32")\n",
        (event->mem_event.out_access & VMI_MEMACCESS_R) ? 'r' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_W) ? 'w' : '-',
        (event->mem_event.out_access & VMI_MEMACCESS_X) ? 'x' : '-',
        event->mem_event.gfn,
        event->mem_event.offset,
        event->mem_event.gla,
        event->vcpu_id
    );
}

void *security_checking_thread(void *arg)
{
    vmi_instance_t vmi = (vmi_instance_t)arg;
    printf("Security Checking Thread Initated: %p\n", vmi);

    int res = 0;
    UNUSED_PARAMETER(res);

    int event_type = INTERRUPTED_EVENT;
    while(!interrupted)
    {
        event_type = event_deque.pop();

        switch (event_type)
        {
            case PUTS_EVENT:{
                printf("Encountered PUTS_EVENT\n");
                break;
            } 
            case OPEN_EVENT:{
                printf("Encountered OPEN_EVENT\n");
                break;
            }
            case CLOSE_EVENT:{
                printf("Encountered CLOSE_EVENT\n");
                break;
            }
            case FORK_EVENT:{
                printf("Encountered FORK_EVENT\n");
                break;
            }
            case INTERRUPTED_EVENT:
            {
                printf("Encountered INTERRUPTED_EVENT\n");
                printf("Security Checking Thread Ended!\n"); 
                /*#ifdef RE_REGISTER_EVENTS
                    // Recheck open files
                    register_open_files_events(vmi, dwarf_fp);
                #endif

                #ifdef ANALYSIS_MODE
                    // Volatility Plugin linux_check_afinfo
                    res = system("python scripts/check_afinfo.py");
                #endif*/
                return NULL;
            }
            default:
            {
                printf("Unknown event encountered\n");
                printf("Security Checking Thread Ended!\n"); 
                return NULL;
            }
        }
    }
    
    printf("Security Checking Thread Ended!\n");
    return NULL;
}
