"""Owned parent/child pidfd_getfd API; no global authorization policy changes."""
import sys
import ctypes
import errno
import os
from pathlib import Path
import socket
libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
libc.prctl(15,b'iosec-pidfd',0,0,0)
def getfd(pidfd,fd,flags=0):
    ctypes.set_errno(0)
    value=libc.syscall(438,pidfd,fd,flags)
    return value,ctypes.get_errno()
def open_leaf(path):
    return os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
def open_middle(path):
    return open_leaf(path)
def open_outer(path):
    return open_middle(path)
def acquire_leaf(pidfd,fd):
    return getfd(pidfd,fd)
def acquire_middle(pidfd,fd):
    return acquire_leaf(pidfd,fd)
def acquire_outer(pidfd,fd):
    return acquire_middle(pidfd,fd)
def write_leaf(fd,data):
    return os.write(fd,data)
def write_middle(fd,data):
    return write_leaf(fd,data)
def write_outer(fd,data):
    return write_middle(fd,data)
root=Path(f'/var/tmp/iosec-pidfd-{os.getpid()}');root.mkdir()
file=root/'owned';parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
target=os.fork()
if target==0:
    parent.close()
    fd=open_outer(file)
    assert os.write(fd,b'initial--')==9;os.lseek(fd,0,os.SEEK_SET)
    child.send(f'{fd} {os.fstat(fd).st_ino}'.encode())
    assert child.recv(64)==b'offset'
    assert os.lseek(fd,0,os.SEEK_CUR)==6;child.send(b'offset=6')
    assert child.recv(64)==b'close';os.close(fd);child.send(b'closed')
    assert child.recv(64)==b'exit';child.close();os._exit(0)
child.close()
try:
    targetfd,inode=map(int,parent.recv(64).split());pidfd=os.pidfd_open(target,0)
    assert getfd(pidfd,targetfd,1)==(-1,errno.EINVAL)
    assert getfd(-1,targetfd)==(-1,errno.EBADF)
    assert getfd(pidfd,1000000)==(-1,errno.EBADF)
    acquired,error=acquire_outer(pidfd,targetfd);assert acquired>=0 and error==0
    assert os.fstat(acquired).st_ino==inode and not os.get_inheritable(acquired)
    assert write_outer(acquired,b'parent')==6
    parent.send(b'offset');assert parent.recv(64)==b'offset=6'
    denied=os.fork()
    if denied==0:
        # Drop this owned caller's uid/capabilities; authorization must reject
        # acquisition from the root-owned target. This never changes YAMA.
        os.close(acquired);os.setresgid(65534,65534,65534);os.setresuid(65534,65534,65534)
        assert getfd(pidfd,targetfd)==(-1,errno.EPERM)
        print(f'PIDFD_DENIED caller={os.getpid()} uid={os.getuid()} errno=1',flush=True)
        os._exit(0)
    assert os.waitpid(denied,0)==(denied,0)
    parent.send(b'close');assert parent.recv(64)==b'closed'
    assert getfd(pidfd,targetfd)==(-1,errno.EBADF)
    parent.send(b'exit');assert os.waitpid(target,0)==(target,0)
    assert not Path(f'/proc/{target}').exists()
    assert getfd(pidfd,targetfd)==(-1,errno.ESRCH)
    alias=os.dup(acquired);os.close(acquired)
    assert write_outer(alias,b'++')==2 and os.pread(alias,9,0)==b'parent++-'
    if len(sys.argv)>1 and sys.argv[1]=='pressure':
        # alias already occupies one of the actual 128 descriptor-label slots.
        filled=[os.dup(alias) for _ in range(127)]
        overflow=os.dup(alias)
        assert write_outer(overflow,b'O')==1
        os.close(overflow)
        for fd in filled:
            os.close(fd)
        recovered=os.dup(alias)
        assert write_outer(recovered,b'R')==1
        assert os.pread(recovered,11,0)==b'parent++OR'
        os.close(recovered);os.close(alias)
        print('PIDFD_PRESSURE_OK filled=128 overflow_write=1 recovery_write=1',flush=True)
    elif len(sys.argv)>1 and sys.argv[1]=='lifetime':
        # The exec child must retain only the explicitly inheritable alias.
        os.set_inheritable(alias,True)
        close_on_exec=os.dup(alias)
        assert not os.get_inheritable(close_on_exec)
        child_exec=os.fork()
        if child_exec==0:
            os.execv(__import__('sys').executable,[__import__('sys').executable,'exec_control.py',str(alias),str(close_on_exec)])
        assert os.waitpid(child_exec,0)==(child_exec,0)
        os.close(close_on_exec)
        assert write_outer(alias,b'P')==1
        # Force a real files_struct copy by retaining a CLONE_FILES reference.
        readfd,writefd=os.pipe()
        share=ctypes.CDLL('./share.so',use_errno=True)
        sharer=share.start_sharer(readfd);assert sharer>0
        assert libc.syscall(272 if os.uname().machine == 'x86_64' else 97,1024)==0,ctypes.get_errno()
        assert write_outer(alias,b'U')==1
        assert os.write(writefd,b'x')==1
        assert os.waitpid(sharer,0)==(sharer,0)
        os.close(readfd);os.close(writefd)
        # Interpreter metadata is untrusted: malformed representation becomes unknown.
        original=write_leaf.__code__
        write_leaf.__code__=original.replace(co_filename='badλ.py')
        assert write_outer(alias,b'?')==1
        write_leaf.__code__=original
        assert write_outer(alias,b'R')==1
        assert os.pread(alias,14,0)==b'parent++EPU?R'
        os.close(alias)
        print('PIDFD_LIFETIME_OK exec=1 cloexec=9 unshare=1 source_unknown=1 fresh=1',flush=True)
    elif len(sys.argv)>1 and sys.argv[1]=='controls':
        # Actual write failure must not be accepted or consume bytes.
        ctypes.set_errno(0)
        assert libc.syscall(1 if os.uname().machine == 'x86_64' else 64,alias,1,2)==-1 and ctypes.get_errno()==errno.EFAULT
        inherited=os.fork()
        if inherited==0:
            assert write_outer(alias,b'F')==1
            os.close(alias);os.close(pidfd);os._exit(0)
        assert os.waitpid(inherited,0)==(inherited,0)
        assert os.pread(alias,10,0)==b'parent++F'
        oldslot=acquired
        os.close(alias)
        # Reuse the same numeric slot for an unrelated file while the pidfd is live.
        other=root/'unrelated'
        replacement=os.open(other,os.O_CREAT|os.O_RDWR,0o600)
        assert replacement==oldslot
        assert write_outer(replacement,b'Z')==1
        os.close(replacement);other.unlink()
        print('PIDFD_CONTROLS_OK fork=1 badwrite=14 unrelated_reuse=1',flush=True)
    else:
        os.close(alias)
    os.close(pidfd)
    print(f'PIDFD_API_OK target={target} targetfd={targetfd} inode={inode} shared_offset=6 departed_target=1 alias_after_exit=1 badflags=22 badpidfd=9 badtarget=9 closedtarget=9 exitedtarget=3 cloexec=1',flush=True)
finally:
    parent.close()
    file.unlink(missing_ok=True);(root/'unrelated').unlink(missing_ok=True);root.rmdir()
