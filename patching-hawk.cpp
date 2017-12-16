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
#include "patching-hawk.h"
  
/////////////////////
// Defines
/////////////////////
#define UNUSED_PARAMETER(expr) (void)(expr);
//#define MYDEBUG
// #define printf(fmt, ...) (void)(0)

#define PAUSE_VM 0

// Event Names Contants
#define INTERRUPTED_EVENT 64
#define EXIT_EVENT 1
#define PUTS_EVENT 2

/////////////////////
// Global Variables
/////////////////////
Deque<int> event_deque;
struct vmi_event_node *vmi_event_head;
string dwarf_fp;

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

static int retrieve_struct_size(string file_path, string struct_name){
    int result = -1;
    ifstream in_file(file_path);

    string struct_substr("<DW_TAG_structure_type> DW_AT_name<\"" + struct_name + "\">");
    string struct_size_substr("DW_AT_byte_size<");
    string line;
    while (getline(in_file, line))
    {
        if (line.find(struct_substr) != string::npos){
            string temp_mem_loc(line.substr(line.find(struct_size_substr) + struct_size_substr.size()));
            result = stoi(temp_mem_loc.substr(0, temp_mem_loc.find(">")), NULL, 16);
            break;
        }
    }

    return result;
}

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

    if(argc != 5)
    {
        fprintf(stderr, "Usage: patching-hawk <VM Name> <VM module.dwarf> <patch process pid> <patched page addr>\n");
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

    vmi_pid_t pid;
    sscanf(argv[3], "%d", &pid);

    addr_t page_addr;
    sscanf(argv[4], "%" PRIx64"", &page_addr);

    register_patched_memory_page(vmi, pid, page_addr);

    // if (register_patched_memory_page(vmi, pid, argv[4]) == FALSE)
    // {
    //     printf("Process not found!\n");

    //     cleanup(vmi);
    //     printf("Naive Event Hawk-Eye Program Ended!\n");
    //     return 4;
    // }

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

    #ifdef ALWAYS_SEND_EVENT
        print_event(event);

        // Read integer from written event address
        addr_t event_addr = (event->mem_event.gfn << 12) + event->mem_event.offset;
        uint32_t event_type;
        vmi_read_32_pa(vmi, event_addr, &event_type);

        printf("Event Type is %d\n", event_type);

        monitored_events_count++;
        vmi_clear_event(vmi, event, NULL);

        #ifdef MONITORING_MODE
            struct event_data *any_data = (struct event_data *) event->data;
            event_deque.push_back(any_data->type);
        #endif

        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

        #ifdef MEASURE_EVENT_CALLBACK_TIME
            t = clock() - t;
            printf("mem_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
        #endif

        return VMI_EVENT_RESPONSE_NONE;

    #else

    // Always clear event on callback
    vmi_clear_event(vmi, event, NULL);

    monitored_events_count++;

    struct event_data *data = (struct event_data *) event->data;
    
    // Check that adddress hit is within monitoring range    
    addr_t event_addr = (event->mem_event.gfn << 12) + event->mem_event.offset;
    addr_t min_addr = data->physical_addr;
    addr_t max_addr = data->physical_addr + data->monitor_size;

    if (event_addr < min_addr || event_addr > max_addr)
    {
        irrelevant_events_count++;

        vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);
        return VMI_EVENT_RESPONSE_NONE;
    }

    #ifdef MONITORING_MODE
        event_deque.push_back(data->type);
    #endif

    vmi_step_event(vmi, event, event->vcpu_id, 1, NULL);

    #ifdef MEASURE_EVENT_CALLBACK_TIME
        t = clock() - t;
        printf("mem_write_cb() took %f seconds to execute \n", ((double)t)/CLOCKS_PER_SEC);
    #endif

    return VMI_EVENT_RESPONSE_NONE;
    #endif
} 

void free_event_data(vmi_event_t *event, status_t rc)
{
    struct event_data * data = (struct event_data *) event->data;
    printf("Freeing data for physical address: \%" PRIx64" from page: \%" PRIx64" due to status %d \n", data->physical_addr, data->physical_addr << 12, rc);
    free(data); 
}

void register_patched_memory_page(vmi_instance_t vmi, vmi_pid_t pid, addr_t page_addr) 
{           
    printf("Registering event for pid: %d and addr: %" PRIx64"\n", pid, page_addr);
    addr_t struct_addr = vmi_translate_uv2p(vmi, page_addr, pid);
    printf("Registering event for physical addr: %" PRIx64"\n", struct_addr);

    // Register write memory event (>> 12 to point to page base)
    vmi_event_t *patch_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
    SETUP_MEM_EVENT(patch_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);
    if (vmi_register_event(vmi, patch_event) == VMI_FAILURE)
    {
        printf("Failed to register event.\n");

        cleanup(vmi);
        printf("Patching Event Hawk-Eye Program Ended!\n");
        return;
    }
    printf("Patching Event Successfuly Registered!\n");
}

/*bool register_patched_process_event(vmi_instance_t vmi, char *req_process) 
{
    printf("Searching for process: %s\n", req_process);
    
    unsigned long tasks_offset = vmi_get_offset(vmi, "linux_tasks");
    unsigned long name_offset = vmi_get_offset(vmi, "linux_name");
    unsigned long pid_offset = vmi_get_offset(vmi, "linux_pid");

    addr_t list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;

    addr_t next_list_entry = list_head;

    // Perform task list walk-through
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    status_t status;

    do 
    {
        current_process = next_list_entry - tasks_offset;

        vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

        procname = vmi_read_str_va(vmi, current_process + name_offset, 0);
        if (!procname) 
        {
            printf("Failed to find procname\n");
            return FALSE;
        }

        if (procname && strcmp(procname, req_process) == 0){
            printf("Found Process with PID: %d and struct addr: \%" PRIx64"\n", pid, current_process);
            free(procname);

            
            // Retrieve process space



            addr_t struct_addr = vmi_translate_kv2p(vmi, current_process);

            // Retrieve signature from memory


            
            printf("Registering event for physical addr: %" PRIx64"\n", struct_addr);
            // Register write memory event (>> 12 to point to page base)
            vmi_event_t *proc_event = (vmi_event_t *) malloc(sizeof(vmi_event_t));
            SETUP_MEM_EVENT(proc_event, struct_addr >> 12, VMI_MEMACCESS_W, mem_write_cb, 0);

            // Setup event context data
            //vmi_read_64_pa(vmi, struct_addr + tasks_offset, &(event_data->next_process));
            //printf("Initial Next Process (struct addr: \%" PRIx64")\n", event_data->next_process - tasks_offset);

            if (vmi_register_event(vmi, proc_event) == VMI_FAILURE)
            {
                printf("Failed to register event.\n");

                cleanup(vmi);
                printf("Patching Event Hawk-Eye Program Ended!\n");
                return FALSE;
            }

            return TRUE;
        }
        
        if (procname) 
        {
            free(procname);
            procname = NULL;
        }

        status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) 
        {
            printf("Failed to read next pointer in loop at %" PRIx64"\n", next_list_entry);
            return FALSE;
        }
    } while(next_list_entry != list_head);

    return FALSE;
}*/

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
                /*#ifdef RE_REGISTER_EVENTS
                    // Recheck processes
                    register_processes_events(vmi, dwarf_fp);
                #endif

                #ifdef ANALYSIS_MODE
                    // Volatility Plugin linux_check_fop
                    res = system("python scripts/check_fop.py");
                    // Volatility Plugin linux_check_creds
                    res = system("python scripts/check_creds.py");
                #endif*/
                break;
            } 
            case EXIT_EVENT:{
                printf("Encountered EXIT_EVENT\n");
                /*#ifdef RE_REGISTER_EVENTS
                    // Recheck open files
                    register_open_files_events(vmi, dwarf_fp);
                #endif

                #ifdef ANALYSIS_MODE
                    // Volatility Plugin linux_check_afinfo
                    res = system("python scripts/check_afinfo.py");
                #endif*/
                break;
            }
            case INTERRUPTED_EVENT:
            {
                printf("Encountered INTERRUPTED_EVENT\n");
                printf("Security Checking Thread Ended!\n"); 
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