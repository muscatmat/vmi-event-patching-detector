#ifndef MMAP_LIST
#define MMAP_LIST

struct mmap_data
{
    addr_t map_start;
    addr_t buffer_addr;

    struct mmap_data *next;
};

struct mmap_data* search_mmap_for_buffer(struct mmap_data *head, addr_t buffer_addr)
{
 
    struct mmap_data *cursor = head;
    while(cursor != NULL)
    {
        if(cursor->map_start == buffer_addr)
            return cursor;

        cursor = cursor->next;
    }
    return NULL;
}
 

#endif