set confirm off
set $dlopen = (void*(*)(char*, int)) __libc_dlopen_mode
set $dlclose = (int(*)(void*)) __libc_dlclose
set $library = $dlopen("/home/muscatmat/Programming/process_patching/patch.so", 1)

#set $putsloc = &'puts@plt'
#disassemble $putsloc

#call $dlclose($library)
#quit
