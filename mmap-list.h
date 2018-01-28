#ifndef MMAP_LIST
#define MMAP_LIST

struct mmap_data
{
    addr_t map_start;
    int map_size;
    addr_t buffer_addr;

    struct mmap_data *next;
};

struct mmap_data* search_mmap_for_buffer(struct mmap_data *head, addr_t buffer_addr)
{
 
    struct mmap_data *cursor = head;
    while(cursor != NULL)
    {
        if(cursor->map_start == buffer_addr && cursor->map_size == 4096)
            return cursor;

        cursor = cursor->next;
    }
    return NULL;
}
 

#endif