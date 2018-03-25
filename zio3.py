#!/usr/bin/env python3
# Mainly borrowed from pexpect. Thanks very much!

__version__ = "3.0.1"
__project__ = "https://github.com/alset0326/zio"

import struct
import socket
import os
import sys
import pty
import time
import re
import select
import termios
import resource
import tty
import errno
import signal
import fcntl
import platform
import datetime
import inspect
import atexit
import ast
import binascii
import abc
import stat
import itertools
from io import BytesIO
from functools import wraps
import builtins

__all__ = ['l8', 'b8', 'l16', 'b16', 'l32', 'b32', 'l64', 'b64', 'zio', 'EOF', 'TIMEOUT', 'SOCKET', 'PROCESS', 'REPR',
           'EVAL', 'HEX', 'UNHEX', 'BIN', 'UNBIN', 'RAW', 'NONE', 'COLORED', 'PIPE', 'TTY', 'TTY_RAW',
           'ensure_str', 'ensure_bytes']

# OS constants
POSIX = os.name == "posix"
WINDOWS = os.name == "nt"
LINUX = sys.platform.startswith("linux")
OSX = sys.platform.startswith("darwin")
FREEBSD = sys.platform.startswith("freebsd")
OPENBSD = sys.platform.startswith("openbsd")
NETBSD = sys.platform.startswith("netbsd")
BSD = FREEBSD or OPENBSD or NETBSD
SUNOS = sys.platform.startswith("sunos") or sys.platform.startswith("solaris")
AIX = sys.platform.startswith("aix")

if WINDOWS:
    raise Exception("zio (version %s) process mode is currently only supported on linux and osx." % __version__)


# Define pack functions

def _lb_wrapper(func):
    endian = func.__name__[0] == 'l' and '<' or '>'
    bits = int(func.__name__[1:])
    pfs = {8: 'B', 16: 'H', 32: 'I', 64: 'Q'}

    @wraps(func)
    def wrapper(*args):
        ret = []
        join = False
        for i in args:
            if isinstance(i, int):
                join = True
                v = struct.pack(endian + pfs[bits], i % (1 << bits))
                ret.append(v)
            elif not i:
                ret.append(None)
            else:
                i = ensure_bytes(i)
                v = struct.unpack(endian + pfs[bits] * (len(i) * 8 // bits), i)
                ret += v
        if join:
            return b''.join(ret)
        elif len(ret) == 1:
            return ret[0]
        elif len(ret) == 0:  # all of the input are empty strings
            return None
        else:
            return ret

    return wrapper


@_lb_wrapper
def l8(*args): pass


@_lb_wrapper
def b8(*args): pass


@_lb_wrapper
def l16(*args): pass


@_lb_wrapper
def b16(*args): pass


@_lb_wrapper
def l32(*args): pass


@_lb_wrapper
def b32(*args): pass


@_lb_wrapper
def l64(*args): pass


@_lb_wrapper
def b64(*args): pass


# Define trigger exceptions

class EOF(Exception):
    """Raised when EOF is read from child or socket.
    This usually means the child has exited or socket shutdown at remote end"""


class TIMEOUT(Exception):
    """Raised when a read timeout exceeds the timeout. """


# Define consts

SOCKET = 'socket'  # zio mode socket
PROCESS = 'process'  # zio mode process
PIPE = 'pipe'  # io mode (process io): send all characters untouched, but use PIPE, so libc cache may apply
TTY = 'tty'  # io mode (process io): normal tty behavier, support Ctrl-C to terminate, and auto \r\n to display more readable lines for human
TTY_RAW = 'ttyraw'  # io mode (process io): send all characters just untouched

# Define print functions. They dealing with bytes not str

ensure_bytes = lambda s: s and (isinstance(s, bytes) and s or s.encode('latin-1')) or b''


def ensure_str(s, encoding=sys.getdefaultencoding()):
    if s and isinstance(s, str):
        return s
    if s and isinstance(s, bytes):
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            return s.decode('latin-1')
    return ''


# colored needed consts
ATTRIBUTES = dict(
    list(zip(['bold', 'dark', '', 'underline', 'blink', '', 'reverse', 'concealed'], list(range(1, 9))))
)
del ATTRIBUTES['']

HIGHLIGHTS = dict(
    list(zip(['on_grey', 'on_red', 'on_green', 'on_yellow', 'on_blue', 'on_magenta', 'on_cyan', 'on_white'],
             list(range(40, 48))))
)

COLORS = dict(
    list(zip(['grey', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white', ],
             list(range(30, 38)))))

RESET = b'\033[0m'


def colored(text: bytes, color: str = None, on_color: str = None, attrs: str = None):
    """ colored copied from termcolor v1.1.0 changing to bytes

    Colorize text.

    Available text colors:
        red, green, yellow, blue, magenta, cyan, white.

    Available text highlights:
        on_red, on_green, on_yellow, on_blue, on_magenta, on_cyan, on_white.

    Available attributes:
        bold, dark, underline, blink, reverse, concealed.

    Example:
        colored('Hello, World!', 'red', 'on_grey', ['blue', 'blink'])
        colored('Hello, World!', 'green')
    """

    if os.getenv('ANSI_COLORS_DISABLED') is None:
        fmt_str = b'\033[%dm%s'
        if color is not None:
            text = fmt_str % (COLORS[color], text)

        if on_color is not None:
            text = fmt_str % (HIGHLIGHTS[on_color], text)

        if attrs is not None:
            for attr in attrs:
                text = fmt_str % (ATTRIBUTES[attr], text)

        text += RESET
    return text


def stdout(s: bytes, color=None, on_color=None, attrs=None):
    """Write bytes to stdout"""
    if not color:
        sys.stdout.buffer.write(s)
    else:
        sys.stdout.buffer.write(colored(s, color, on_color, attrs))
    sys.stdout.flush()


def log(s: bytes, color=None, on_color=None, attrs=None, new_line=True, timestamp=False, f=sys.stderr):
    if timestamp is True:
        now = ensure_bytes(datetime.datetime.now().strftime('[%Y-%m-%d_%H:%M:%S]'))
    elif timestamp is False:
        now = None
    elif timestamp:
        now = timestamp
    else:
        now = None
    if color:
        s = colored(s, color, on_color, attrs)
    if now:
        f.write(now)
        f.write(b' ')
    f.buffer.write(s)
    if new_line:
        f.buffer.write(b'\n')
    f.flush()


def COLORED(f, color='cyan', on_color=None, attrs=None): return lambda s: colored(f(s), color, on_color, attrs)


def REPR(s): return ensure_bytes(repr(s)) + b'\r\n'


def EVAL(s):  # now you are not worried about pwning yourself
    return ast.literal_eval(s)


def HEX(s): return binascii.b2a_hex(s) + b'\r\n'


# hex-strings with odd length are now acceptable
def UNHEX(s): s = s.strip(); return binascii.a2b_hex(len(s) % 2 and b'0' + s or s)


def BIN(s): return ensure_bytes(''.join((bin(x)[2:] for x in s)) + '\r\n')


def UNBIN(s): s = s.strip(); return b''.join((bytes((int(s[i:i + 8], 2),)) for i in range(0, len(s), 8)))


def RAW(s): return s


def NONE(s): raise Exception("I'm NONE why call me?")


# Define zio base class

class ZioBase(object, metaclass=abc.ABCMeta):
    """
    |
    | str/bytes <->  user API
    |-----------
    | bytes     ->  class buffer
    |-----------
    | bytes     ->  syscall read/write, stdout
    |
    """
    linesep = ensure_bytes(os.linesep)
    allowed_string_types = (bytes, str)
    string_type = bytes
    buffer_type = BytesIO  # Expecter used
    STDIN_FILENO = pty.STDIN_FILENO
    STDOUT_FILENO = pty.STDOUT_FILENO
    STDERR_FILENO = pty.STDERR_FILENO

    def __init__(self, target, *, print_read=RAW, print_write=RAW, timeout=8, write_delay=0.05, ignorecase=False,
                 debug=None):
        if not target:
            raise Exception('cmdline or socket not provided for zio, try zio("ls -l")')

        # Store args

        self.debug = debug
        self.target = target
        self.print_read = print_read
        self.print_write = print_write
        self.ignorecase = ignorecase

        if isinstance(timeout, int) and timeout > 0:
            self.timeout = timeout
        else:
            self.timeout = 8

        self.write_delay = write_delay  # the delay before writing data, pexcept said Linux don't like this to be below 30ms
        self.close_delay = 0.1  # like pexcept, will used by close(), to give kernel time to update process status, time in seconds
        self.terminate_delay = 0.1  # like close_delay

        # Init inside variables
        # close and eof flag
        self.flag_eof = False
        self.closed = True
        # fileno
        self.readfd = -1
        self.writefd = -1
        # core buffer
        self._buffer = self.buffer_type()
        # search result
        self.before = self.after = self.match = self.string_type()
        self.match_index = None
        # max bytes to read at one time into buffer
        self.maxread = 2000
        # Delay in seconds to sleep after each call to read_nonblocking().
        self.delayafterread = None
        # Data before searchwindowsize point is preserved, but not searched.
        self.searchwindowsize = None

    # Define properties

    @property
    def buffer(self):
        return self._buffer.getvalue()

    @buffer.setter
    def buffer(self, value):
        self._buffer = self.buffer_type()
        self._buffer.write(value)

    @property
    def print_read(self):
        return self._print_read and (self._print_read is not NONE)

    @print_read.setter
    def print_read(self, value):
        if value is True:
            self._print_read = RAW
        elif value is False:
            self._print_read = NONE
        elif callable(value):
            self._print_read = value
        else:
            raise Exception('Bad print_read value')

        assert callable(self._print_read) and len(inspect.getfullargspec(self._print_read).args) == 1

    @property
    def print_write(self):
        return self._print_write and (self._print_write is not NONE)

    @print_write.setter
    def print_write(self, value):
        if value is True:
            self._print_write = RAW
        elif value is False:
            self._print_write = NONE
        elif callable(value):
            self._print_write = value
        else:
            raise Exception('Bad print_write value')

        assert callable(self._print_write) and len(inspect.getfullargspec(self._print_write).args) == 1

    # Define flag functions

    def eof(self):

        """This returns True if the EOF exception was ever raised.
        """

        return self.flag_eof

    def flush(self):
        """
        just keep to be a file-like object
        """
        pass

    # Define write functions

    def _pattern_type_err(self, pattern):
        """Copy from pexpect"""
        raise TypeError('got {badtype} ({badobj!r}) as pattern, must be one of: {goodtypes}, zio3.EOF, zio3.TIMEOUT'
                        .format(badtype=type(pattern), badobj=pattern,
                                goodtypes=', '.join([str(ast) for ast in self.allowed_string_types])))

    def write(self, s):
        """
        :param s: bytes/str
        :return: len
        """
        if not s: return 0
        s = ensure_bytes(s)
        if self.print_write:
            stdout(self._print_write(s))
        return self._write(s)

    def writeline(self, s=''):
        """
        :param s: str/bytes
        :return: len (include linesep)
        """
        s = ensure_bytes(s)
        return self.write(s + self.linesep)

    def writelines(self, sequence):
        """
        :param sequence: list/tuple
        :return: len (include linesep)
        """
        return sum((self.writeline(i) for i in sequence))

    # Define read functions

    def expect_exact(self, pattern_list, timeout=-1, searchwindowsize=None):
        """Expect string list. Copy from pexpect expect_exact. Return match index."""
        if timeout == -1:
            timeout = self.timeout

        if (isinstance(pattern_list, self.allowed_string_types) or
                pattern_list in (TIMEOUT, EOF)):
            pattern_list = [pattern_list]

        def prepare_pattern(pattern):
            if pattern in (TIMEOUT, EOF):
                return pattern
            if isinstance(pattern, self.allowed_string_types):
                return ensure_bytes(pattern)
            self._pattern_type_err(pattern)

        try:
            pattern_list = iter(pattern_list)
        except TypeError:
            self._pattern_type_err(pattern_list)
        pattern_list = [prepare_pattern(p) for p in pattern_list]

        exp = Expecter(self, searcher_string(pattern_list), searchwindowsize)
        return exp.expect_loop(timeout)

    def compile_pattern_list(self, patterns):
        """Copy from pexpect compile_pattern_list"""

        if patterns is None:
            return []
        if not isinstance(patterns, list):
            patterns = [patterns]

        # Allow dot to match \n
        compile_flags = re.DOTALL
        if self.ignorecase:
            compile_flags = compile_flags | re.IGNORECASE
        compiled_pattern_list = []
        for idx, p in enumerate(patterns):
            if isinstance(p, self.allowed_string_types):
                p = ensure_bytes(p)
                compiled_pattern_list.append(re.compile(p, compile_flags))
            elif p is EOF:
                compiled_pattern_list.append(EOF)
            elif p is TIMEOUT:
                compiled_pattern_list.append(TIMEOUT)
            elif isinstance(p, type(re.compile(''))):
                compiled_pattern_list.append(p)
            else:
                self._pattern_type_err(p)
        return compiled_pattern_list

    def expect(self, pattern, timeout=-1, searchwindowsize=-1):
        """Expect re. Copy from pexpect expect. Return match index"""
        compiled_pattern_list = self.compile_pattern_list(pattern)
        return self.expect_list(compiled_pattern_list, timeout, searchwindowsize)

    def expect_list(self, pattern_list, timeout=-1, searchwindowsize=-1):
        """Expect re list. Copy from pexpect expect_list. Return match index"""
        if timeout == -1:
            timeout = self.timeout
        exp = Expecter(self, searcher_re(pattern_list), searchwindowsize)
        return exp.expect_loop(timeout)

    def read_nonblocking(self, size=1, timeout=-1):
        """Copy from pexpect read_nonblocking"""
        if self.closed:
            raise ValueError('I/O operation on closed file.')

        if timeout == -1:
            timeout = self.timeout

            # Note that some systems such as Solaris do not give an EOF when
            # the child dies. In fact, you can still try to read
            # from the child_fd -- it will block forever or until TIMEOUT.
            # For this case, I test isalive() before doing any reading.
            # If isalive() is false, then I pretend that this is the same as EOF.
        if not self.isalive():
            # timeout of 0 means "poll"
            r, w, e = select_ignore_interrupts([self.readfd], [], [], 0)
            if not r:
                self.flag_eof = True
                raise EOF('End Of File (EOF). Braindead platform.')

        r, w, e = select_ignore_interrupts([self.readfd], [], [], timeout)

        if not r:
            if not self.isalive():
                # Some platforms, such as Irix, will claim that their
                # processes are alive; timeout on the select; and
                # then finally admit that they are not alive.
                self.flag_eof = True
                raise EOF('End of File (EOF). Very slow platform.')
            else:
                raise TIMEOUT('Timeout exceeded.')

        if self.readfd in r:
            try:
                s = self._read(size)
            except OSError as err:
                if err.args[0] == errno.EIO:
                    # Linux-style EOF
                    self.flag_eof = True
                    raise EOF('End Of File (EOF). Exception style platform.')
                raise
            if s == b'':
                # BSD-style EOF
                self.flag_eof = True
                raise EOF('End Of File (EOF). Empty string style platform.')

            if self.print_read:
                stdout(self._print_read(s))
            return s

        raise Exception('Reached an unexpected state.')  # pragma: no cover

    def read(self, size=-1, timeout=-1):
        """Copy from pexpect read"""
        if size == 0:
            return self.string_type()
        if size < 0:
            # read until EOF
            self.expect(EOF)
            return self.before

        cre = re.compile(ensure_bytes('.{%d}' % size), re.DOTALL)
        index = self.expect([cre, EOF])
        if index == 0:
            # assert self.before == self.string_type()  # Maybe not assert?
            return self.after
        return self.before

    def read_until_timeout(self, timeout=0.05):
        if timeout is not None and timeout > 0:
            end_time = time.time() + timeout
        else:
            end_time = float('inf')
        old_data = self.buffer
        try:
            while True:
                now = time.time()
                if now > end_time: break
                if timeout is not None and timeout > 0:
                    timeout = end_time - now
                old_data += self.read_nonblocking(2048, timeout)
        except EOF:
            err = sys.exc_info()[1]
            self._buffer = self.buffer_type()
            self.before = self.string_type()
            self.after = EOF
            self.match = old_data
            self.match_index = None
            raise EOF(str(err) + '\n' + str(self))
        except TIMEOUT:
            self._buffer = self.buffer_type()
            self.before = self.string_type()
            self.after = TIMEOUT
            self.match = old_data
            self.match_index = None
            return old_data
        except:
            self.before = self.string_type()
            self.after = None
            self.match = old_data
            self.match_index = None
            raise

    read_eager = read_until_timeout

    # def readable(self):
    #     return select_ignore_interrupts([self.readfd], [], [], 0) == ([self.readfd], [], [])

    def readline(self, size=-1):
        """Copy and modify from pexpect readline"""
        if size == 0:
            return self.string_type()
        lineseps = [b'\r\n', b'\n', EOF]
        index = self.expect(lineseps)
        if index < 2:
            return self.before + lineseps[index]
        else:
            return self.before

    read_line = readline

    def readlines(self, sizehint=sys.maxsize):
        return [i for i in itertools.islice(iter(self.readline, b''), 0, sizehint)]

    read_lines = readlines

    def read_until(self, pattern_list, timeout=-1, searchwindowsize=None):
        matched = self.expect_exact(pattern_list, timeout, searchwindowsize)
        ret = self.before
        if isinstance(self.after, self.string_type):
            ret += self.after  # after is the matched string, before is the string before this match
        return ret  # be compatible with telnetlib.read_until

    def read_until_re(self, pattern, timeout=-1, searchwindowsize=None):
        matched = self.expect(pattern, timeout, searchwindowsize)
        ret = self.before
        if isinstance(self.after, self.string_type):
            ret += self.after
        return ret

    def gdb_hint(self, breakpoints=None, relative=None, extras=None):
        # disable timeout while using gdb_hint
        self.timeout = None
        pid = self.pid
        if not pid:
            input('[ WARN ] pid unavailable to attach gdb, please find out the pid by your own. '
                  'Press enter to continue ...')
            return
        hints = ['attach %d' % pid]
        base = 0
        if relative:
            vmmap = open('/proc/%d/maps' % pid).read()
            for line in vmmap.splitlines():
                if line.lower().find(relative.lower()) > -1:
                    base = int(line.split('-')[0], 16)
                    break
        if breakpoints:
            for b in breakpoints:
                hints.append('b *' + hex(base + b))
        if extras:
            for e in extras:
                hints.append(str(e))

        gdb = 'gdb' + ''.join((' -eval-command  "' + i + '"' for i in hints)) + \
              '\nuse cmdline above to attach gdb then press enter to continue ...'
        input(gdb)

    def _not_impl(self, hint="Not Implemented"):
        raise NotImplementedError(hint)

    # apis below
    read_after = read_before = read_between = read_range = _not_impl

    @abc.abstractmethod
    def terminate(self, force=False):
        pass

    @abc.abstractmethod
    def wait(self):
        pass

    @abc.abstractmethod
    def isalive(self):
        pass

    @abc.abstractmethod
    def interact(self, escape_character=None, input_filter=None, output_filter=None, raw_rw=True):
        pass

    @abc.abstractmethod
    def end(self, force_close=False):
        pass

    @abc.abstractmethod
    def close(self, force=True):
        pass

    @abc.abstractmethod
    def _read(self, size):
        pass

    @abc.abstractmethod
    def _write(self, s):
        pass

    @property
    @abc.abstractmethod
    def pid(self):
        pass


class ZioSocket(ZioBase):

    def __init__(self, target, *, print_read=RAW, print_write=RAW, timeout=8, write_delay=0.05, ignorecase=False,
                 debug=None):
        super().__init__(target, print_read=print_read, print_write=print_write, timeout=timeout,
                         write_delay=write_delay, ignorecase=ignorecase, debug=debug)

        if isinstance(self.target, socket.socket):
            self.sock = self.target
            self.name = repr(self.target)
        else:
            self.sock = socket.create_connection(self.target, self.timeout)
            self.name = '<socket ' + self.target[0] + ':' + str(self.target[1]) + '>'
        self.readfd = self.writefd = self.sock.fileno()
        self.closed = False

    def __str__(self):
        ret = ['io-mode: SOCKET',
               'name: {}'.format(self.name),
               'timeout: {}'.format(self.timeout),
               'write-fd: {}'.format(self.writefd),
               'read-fd: {}'.format(self.readfd),
               'buffer(last 100 chars): {}'.format(repr(ensure_str(self.buffer[-100:]))),
               'eof: {}'.format(self.flag_eof)]
        return '\n'.join(ret)

    def terminate(self, force=False):
        self.close()

    def wait(self):
        return self.read_until_timeout()

    def isalive(self):

        """This tests if the child process is running or not. This is
        non-blocking. If the child was terminated then this will read the
        exit code or signalstatus of the child. This returns True if the child
        process appears to be running or False if not. It can take literally
        SECONDS for Solaris to return the right status. """

        return not self.flag_eof

    def interact(self, escape_character=None, input_filter=None, output_filter=None, raw_rw=True):
        if self.print_read: stdout(self._print_read(self.buffer))
        self._buffer = self.buffer_type()
        if escape_character is not None:
            escape_character = ensure_bytes(escape_character)
        while self.isalive():
            r, w, e = select_ignore_interrupts([self.readfd, self.STDIN_FILENO], [], [])
            if self.readfd in r:
                try:
                    data = self._read(1024)
                except OSError as err:
                    if err.args[0] == errno.EIO:
                        # Linux-style EOF
                        self.flag_eof = True
                        break
                    raise
                if data == b'':
                    # BSD-style EOF
                    self.flag_eof = True
                    break
                if output_filter:
                    data = output_filter(data)
                stdout(raw_rw and data or self._print_read(data))
            if self.STDIN_FILENO in r:
                data = os.read(self.STDIN_FILENO, 1024)
                if input_filter:
                    data = input_filter(data)
                i = -1
                if escape_character is not None:
                    i = data.rfind(escape_character)
                if i != -1:
                    data = data[:i]
                    self._write(data)
                    break
                self._write(data)

    def end(self, force_close=False):
        """
        end of writing stream, but we can still read
        """
        self.sock.shutdown(socket.SHUT_WR)

    def close(self, force=True):
        """
        close and clean up, nothing can and should be done after closing
        """
        if self.closed:
            return
        if self.sock:
            self.sock.close()
        self.sock = None
        self.flag_eof = True
        self.closed = True
        self.readfd = -1
        self.writefd = -1

    def _read(self, size):
        try:
            return self.sock.recv(size)
        except socket.error as err:
            if err.args[0] == errno.ECONNRESET:
                raise EOF('Connection reset by peer')
            raise err

    def _write(self, s):
        self.sock.sendall(s)
        return len(s)

    @property
    def pid(self):
        # code borrowed from https://github.com/Gallopsled/pwntools to implement gdb attach of local socket
        if OSX:
            # osx cannot get pid of a socket yet
            return None

        def toaddr(arg: tuple):
            """
            (host, port)
            :return:
            """
            return '%08X:%04X' % (l32(socket.inet_aton(arg[0])), arg[1])

        def getpid(loc, rem):
            loc = toaddr(loc)
            rem = toaddr(rem)
            inode = 0
            with open('/proc/net/tcp') as fd:
                for line in fd:
                    line = line.split()
                    if line[1] == loc and line[2] == rem:
                        inode = line[9]
            if inode == 0:
                return []
            for pid in all_pids():
                try:
                    for fd in os.listdir('/proc/%d/fd' % pid):
                        fd = os.readlink('/proc/%d/fd/%s' % (pid, fd))
                        m = re.match('socket:\[(\d+)\]', fd)
                        if m:
                            this_inode = m.group(1)
                            if this_inode == inode:
                                return pid
                except:
                    pass

        sock = self.sock.getsockname()
        peer = self.sock.getpeername()
        pids = [getpid(peer, sock), getpid(sock, peer)]
        if pids[0]: return pids[0]
        if pids[1]: return pids[1]
        return None


class ZioProcess(ZioBase):
    CHILD = pty.CHILD

    def __init__(self, target, *, stdin=PIPE, stdout=TTY_RAW, print_read=RAW, print_write=RAW, timeout=8, cwd=None,
                 env=None, sighup=signal.SIG_DFL, write_delay=0.05, ignorecase=False, debug=None):

        super().__init__(target, print_read=print_read, print_write=print_write, timeout=timeout,
                         write_delay=write_delay, ignorecase=ignorecase, debug=debug)
        self.stdin = stdin
        self.stdout = stdout
        self.cwd = cwd
        self.env = env
        self.sighup = sighup

        # Set exit code
        self.exit_code = None

        # spawn process below
        self.child_pid = None
        self.closed = False

        if isinstance(target, bytes):
            target = ensure_str(target)
        elif isinstance(target, tuple):
            target = list(target)

        if isinstance(target, str):
            self.args = split_command_line(target)
            self.command = self.args[0]
        elif isinstance(target, list):
            self.args = target
            self.command = self.args[0]
        else:
            raise Exception('Unknown target type')

        command_with_path = which(self.command)
        if command_with_path is None:
            raise Exception('zio (process mode) Command not found in path: %s' % self.command)

        self.command = command_with_path
        self.args[0] = self.command
        self.name = '<' + ' '.join(self.args) + '>'

        # Delay in seconds to sleep after each call to read_nonblocking().
        # Set this to None to skip the time.sleep() call completely: that
        # would restore the behavior from pexpect-2.0 (for performance
        # reasons or because you don't want to release Python's global
        # interpreter lock).
        self.delayafterread = 0.0001

        self._spawn()

    def _spawn(self):
        exec_err_pipe_read, exec_err_pipe_write = os.pipe()

        if self.stdout == PIPE:
            stdout_slave_fd, stdout_master_fd = self.pipe_cloexec()
        else:
            stdout_master_fd, stdout_slave_fd = pty.openpty()
        if stdout_master_fd < 0 or stdout_slave_fd < 0: raise Exception(
            'Could not create pipe or openpty for stdout/stderr')

        # use another pty for stdin because we don't want our input to be echoed back in stdout
        # set echo off does not help because in application like ssh, when you input the password
        # echo will be switched on again
        # and dont use os.pipe either, because many thing weired will happen, such as baskspace not working, ssh lftp command hang

        stdin_master_fd, stdin_slave_fd = self.stdin == PIPE and self.pipe_cloexec() or pty.openpty()
        if stdin_master_fd < 0 or stdin_slave_fd < 0: raise Exception('Could not openpty for stdin')

        pid = os.fork()

        if pid < 0:
            raise Exception('failed to fork')
        elif pid == self.CHILD:  # Child
            os.close(stdout_master_fd)

            if os.isatty(stdin_slave_fd):
                self._pty_make_controlling_tty(stdin_slave_fd)

            # Dup fds for child
            def _dup2(a, b):
                # dup2() removes the CLOEXEC flag but
                # we must do it ourselves if dup2()
                # would be a no-op (python issue #10806).
                if a == b:
                    self._set_cloexec_flag(a, False)
                elif a is not None:
                    os.dup2(a, b)

            # redirect stdout and stderr to pty
            os.dup2(stdout_slave_fd, self.STDOUT_FILENO)
            os.dup2(stdout_slave_fd, self.STDERR_FILENO)

            # redirect stdin to stdin_slave_fd instead of stdout_slave_fd, to prevent input echoed back
            _dup2(stdin_slave_fd, self.STDIN_FILENO)

            if stdout_slave_fd > self.STDERR_FILENO:
                os.close(stdout_slave_fd)

            if stdin_master_fd is not None:
                os.close(stdin_master_fd)

            # set window size
            try:
                if os.isatty(stdout_slave_fd) and os.isatty(self.STDIN_FILENO):
                    h, w = self.getwinsize(0)
                    self.setwinsize(stdout_slave_fd, h, w)  # note that this may not be successful
            except IOError as err:
                if self.debug: log('[ WARN ] setwinsize exception: %s' % (str(err)), f=self.debug)
                if err.args[0] not in (errno.EINVAL, errno.ENOTTY):
                    raise

            # [pexpect issue #119] 3. The child closes the reading end and sets the
            # close-on-exec flag for the writing end.
            os.close(exec_err_pipe_read)
            fcntl.fcntl(exec_err_pipe_write, fcntl.F_SETFD, fcntl.FD_CLOEXEC)

            # Do not allow child to inherit open file descriptors from parent,
            # with the exception of the exec_err_pipe_write of the pipe
            max_fd = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
            os.closerange(self.STDERR_FILENO + 1, exec_err_pipe_write)
            os.closerange(exec_err_pipe_write + 1, max_fd)

            # the following line matters, for example, if SIG_DFL specified and sighup sent when exit, the exitcode of child process can be affected to 1
            if self.sighup is not None:
                # note that, self.signal could only be one of (SIG_IGN, SIG_DFL)
                signal.signal(signal.SIGHUP, self.sighup)

            if self.cwd is not None:
                os.chdir(self.cwd)

            try:
                if self.env is None:
                    os.execv(self.command, self.args)
                else:
                    os.execvpe(self.command, self.args, self.env)
            except OSError as err:
                # [pexpect issue #119] 5. If exec fails, the child writes the error
                # code back to the parent using the pipe, then exits.
                tosend = 'OSError:{}:{}'.format(err.errno, str(err))
                tosend = tosend.encode('utf-8')
                os.write(exec_err_pipe_write, tosend)
                os.close(exec_err_pipe_write)
                os._exit(os.EX_OSERR)

        # parent
        # [pexpect issue #119] 2. After forking, the parent closes the writing end
        # of the pipe and reads from the reading end.
        os.close(exec_err_pipe_write)
        exec_err_data = os.read(exec_err_pipe_read, 4096)
        os.close(exec_err_pipe_read)

        # [pexepect issue #119] 6. The parent reads eof (a zero-length read) if the
        # child successfully performed exec, since close-on-exec made
        # successful exec close the writing end of the pipe. Or, if exec
        # failed, the parent reads the error code and can proceed
        # accordingly. Either way, the parent blocks until the child calls
        # exec.
        if len(exec_err_data) != 0:
            try:
                errclass, errno_s, errmsg = exec_err_data.split(b':', 2)
                exctype = getattr(builtins, errclass.decode('ascii'), Exception)

                exception = exctype(errmsg.decode('utf-8', 'replace'))
                if exctype is OSError:
                    exception.errno = int(errno_s)
            except:
                raise Exception('Subprocess failed, got bad error data: %r'
                                % exec_err_data)
            else:
                raise exception

        self.child_pid = pid
        self.writefd = stdin_master_fd
        self.readfd = stdout_master_fd

        if os.isatty(self.writefd):
            # there is no way to eliminate controlling characters in tcattr
            # so we have to set raw mode here now
            self._wfd_init_mode = tty.tcgetattr(self.writefd)[:]
            if self.stdin == TTY_RAW:
                self.ttyraw(self.writefd)
                self._wfd_raw_mode = tty.tcgetattr(self.writefd)[:]
            else:
                self._wfd_raw_mode = self._wfd_init_mode[:]

        if os.isatty(self.readfd):
            self._rfd_init_mode = tty.tcgetattr(self.readfd)[:]
            if self.stdout == TTY_RAW:
                self.ttyraw(self.readfd, raw_in=False, raw_out=True)
                self._rfd_raw_mode = tty.tcgetattr(self.readfd)[:]
                if self.debug: log('stdout tty raw mode: %r' % self._rfd_raw_mode, f=self.debug)
            else:
                self._rfd_raw_mode = self._rfd_init_mode[:]

        os.close(stdin_slave_fd)
        os.close(stdout_slave_fd)

        time.sleep(self.close_delay)

        atexit.register(self.kill, signal.SIGHUP)

    def _pty_make_controlling_tty(self, tty_fd):
        """This makes the pseudo-terminal the controlling tty. This should be
        more portable than the pty.fork() function. Specifically, this should
        work on Solaris. """

        child_name = os.ttyname(tty_fd)

        # Disconnect from controlling tty, if any.  Raises OSError of ENXIO
        # if there was no controlling tty to begin with, such as when
        # executed by a cron(1) job.
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            os.close(fd)
        except OSError as err:
            if err.errno != errno.ENXIO:
                raise

        os.setsid()

        # Verify we are disconnected from controlling tty by attempting to open
        # it again.  We expect that OSError of ENXIO should always be raised.
        try:
            fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            os.close(fd)
            raise Exception("OSError of errno.ENXIO should be raised.")
        except OSError as err:
            if err.errno != errno.ENXIO:
                raise

        # Verify we can open child pty.
        fd = os.open(child_name, os.O_RDWR)
        os.close(fd)

        # Verify we now have a controlling tty.
        fd = os.open("/dev/tty", os.O_WRONLY)
        os.close(fd)

    def _set_cloexec_flag(self, fd, cloexec=True):
        try:
            cloexec_flag = fcntl.FD_CLOEXEC
        except AttributeError:
            cloexec_flag = 1

        old = fcntl.fcntl(fd, fcntl.F_GETFD)
        if cloexec:
            fcntl.fcntl(fd, fcntl.F_SETFD, old | cloexec_flag)
        else:
            fcntl.fcntl(fd, fcntl.F_SETFD, old & ~cloexec_flag)

    def pipe_cloexec(self):
        """Create a pipe with FDs set CLOEXEC."""
        # Pipes' FDs are set CLOEXEC by default because we don't want them
        # to be inherited by other subprocesses: the CLOEXEC flag is removed
        # from the child's FDs by _dup2(), between fork() and exec().
        # This is not atomic: we would need the pipe2() syscall for that.
        r, w = os.pipe()
        self._set_cloexec_flag(r)
        self._set_cloexec_flag(w)
        return w, r

    def setwinsize(self, fd, rows, cols):  # from pexpect, thanks!

        """This sets the terminal window size of the child tty. This will cause
        a SIGWINCH signal to be sent to the child. This does not change the
        physical window size. It changes the size reported to TTY-aware
        applications like vi or curses -- applications that respond to the
        SIGWINCH signal. """

        # Check for buggy platforms. Some Python versions on some platforms
        # (notably OSF1 Alpha and RedHat 7.1) truncate the value for
        # termios.TIOCSWINSZ. It is not clear why this happens.
        # These platforms don't seem to handle the signed int very well;
        # yet other platforms like OpenBSD have a large negative value for
        # TIOCSWINSZ and they don't have a truncate problem.
        # Newer versions of Linux have totally different values for TIOCSWINSZ.
        # Note that this fix is a hack.
        TIOCSWINSZ = getattr(termios, 'TIOCSWINSZ', -2146929561)
        if TIOCSWINSZ == 2148037735:
            # Same bits, but with sign.
            TIOCSWINSZ = -2146929561
        # Note, assume ws_xpixel and ws_ypixel are zero.
        s = struct.pack('HHHH', rows, cols, 0, 0)
        fcntl.ioctl(fd, TIOCSWINSZ, s)

    def getwinsize(self, fd):

        """This returns the terminal window size of the child tty. The return
        value is a tuple of (rows, cols). """

        TIOCGWINSZ = getattr(termios, 'TIOCGWINSZ', 1074295912)
        s = struct.pack('HHHH', 0, 0, 0, 0)
        x = fcntl.ioctl(fd, TIOCGWINSZ, s)
        return struct.unpack('HHHH', x)[0:2]

    def __str__(self):
        ret = ('io-mode: PROCESS',
               'name: {}'.format(self.name),
               'timeout: {}'.format(self.timeout),
               'write-fd: {}'.format(self.writefd),
               'read-fd: {}'.format(self.readfd),
               'buffer(last 100 chars): {}'.format(repr(ensure_str(self.buffer[-100:]))),
               'eof: {}'.format(self.flag_eof),
               'command: {}'.format(str(self.command)),
               'args: {:s}'.format(repr(self.args)),
               'write-delay: {:f}'.format(self.write_delay),
               'close-delay: {:f}'.format(self.close_delay),)
        return '\n'.join(ret)

    def terminate(self, force=False):
        """Copy from pexpect terminate"""

        if not self.isalive():
            return True
        try:
            self.kill(signal.SIGHUP)
            time.sleep(self.terminate_delay)
            if not self.isalive():
                return True
            self.kill(signal.SIGCONT)
            time.sleep(self.terminate_delay)
            if not self.isalive():
                return True
            self.kill(signal.SIGINT)  # SIGTERM is nearly identical to SIGINT
            time.sleep(self.terminate_delay)
            if not self.isalive():
                return True
            if force:
                self.kill(signal.SIGKILL)
                time.sleep(self.terminate_delay)
                if not self.isalive():
                    return True
                else:
                    return False
            return False
        except OSError:
            # I think there are kernel timing issues that sometimes cause
            # this to happen. I think isalive() reports True, but the
            # process is dead to the kernel.
            # Make one last attempt to see if the kernel is up to date.
            time.sleep(self.terminate_delay)
            if not self.isalive():
                return True
            else:
                return False

    def kill(self, sig):

        """This sends the given signal to the child application. In keeping
        with UNIX tradition it has a misleading name. It does not necessarily
        kill the child unless you send the right signal. """

        # Same as os.kill, but the pid is given for you.
        if self.isalive():
            os.kill(self.child_pid, sig)

    def wait(self):

        """This waits until the child exits. This is a blocking call. This will
        not read any data from the child, so this will block forever if the
        child has unread output and has terminated. In other words, the child
        may have printed output then called exit(), but, the child is
        technically still alive until its output is read by the parent. """

        if self.isalive():
            pid, status = os.waitpid(self.child_pid, 0)
        else:
            raise Exception('Cannot wait for dead child process.')
        self.exit_code = os.WEXITSTATUS(status)
        if os.WIFEXITED(status):
            self.exit_code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            self.exit_code = os.WTERMSIG(status)
        elif os.WIFSTOPPED(status):
            # You can't call wait() on a child process in the stopped state.
            raise Exception('Called wait() on a stopped child ' +
                            'process. This is not supported. Is some other ' +
                            'process attempting job control with our child pid?')
        return self.exit_code

    def isalive(self):

        """This tests if the child process is running or not. This is
        non-blocking. If the child was terminated then this will read the
        exit code or signalstatus of the child. This returns True if the child
        process appears to be running or False if not. It can take literally
        SECONDS for Solaris to return the right status. """

        if self.exit_code is not None:
            return False

        if self.flag_eof:
            # This is for Linux, which requires the blocking form
            # of waitpid to # get status of a defunct process.
            # This is super-lame. The flag_eof would have been set
            # in read_nonblocking(), so this should be safe.
            waitpid_options = 0
        else:
            waitpid_options = os.WNOHANG

        try:
            pid, status = os.waitpid(self.child_pid, waitpid_options)
        except OSError as e:
            # No child processes
            if e.errno == errno.ECHILD:
                raise Exception('isalive() encountered condition ' +
                                'where "terminated" is 0, but there was no child ' +
                                'process. Did someone else call waitpid() ' +
                                'on our process?')
            else:
                raise

        # I have to do this twice for Solaris.
        # I can't even believe that I figured this out...
        # If waitpid() returns 0 it means that no child process
        # wishes to report, and the value of status is undefined.
        if pid == 0:
            try:
                ### os.WNOHANG) # Solaris!
                pid, status = os.waitpid(self.child_pid, waitpid_options)
            except OSError as e:
                # This should never happen...
                if e.errno == errno.ECHILD:
                    raise Exception('isalive() encountered condition ' +
                                    'that should never happen. There was no child ' +
                                    'process. Did someone else call waitpid() ' +
                                    'on our process?')
                else:
                    raise

            # If pid is still 0 after two calls to waitpid() then the process
            # really is alive. This seems to work on all platforms, except for
            # Irix which seems to require a blocking call on waitpid or select,
            # so I let read_nonblocking take care of this situation
            # (unfortunately, this requires waiting through the timeout).
            if pid == 0:
                return True

        if pid == 0:
            return True

        if os.WIFEXITED(status):
            self.exit_code = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            self.exit_code = os.WTERMSIG(status)
        elif os.WIFSTOPPED(status):
            raise Exception('isalive() encountered condition ' +
                            'where child process is stopped. This is not ' +
                            'supported. Is some other process attempting ' +
                            'job control with our child pid?')
        return False

    def interact(self, escape_character=None, input_filter=None, output_filter=None, raw_rw=True):
        """
        when stdin is passed using os.pipe, backspace key will not work as expected,
        if wfd is not a tty, then when backspace pressed, I can see that 0x7f is passed, but vim does not delete backwards, so you should choose the right input when using zio
        """

        if self.print_read: stdout(self._print_read(self.buffer))
        self._buffer = self.buffer_type()
        # if input_filter is not none, we should let user do some line editing
        if not input_filter and os.isatty(self.STDIN_FILENO):
            mode = tty.tcgetattr(self.STDIN_FILENO)  # mode will be restored after interact
            self.ttyraw(self.STDIN_FILENO)  # set to raw mode to pass all input thru, supporting apps as vim
        if os.isatty(self.writefd):
            # here, enable cooked mode for process stdin
            # but we should only enable for those who need cooked mode, not stuff like vim
            # we just do a simple detection here
            wfd_mode = tty.tcgetattr(self.writefd)
            if self.debug:
                log('wfd now mode = ' + repr(wfd_mode), f=self.debug)
                log('wfd raw mode = ' + repr(self._wfd_raw_mode), f=self.debug)
                log('wfd ini mode = ' + repr(self._wfd_init_mode), f=self.debug)
            if wfd_mode == self._wfd_raw_mode:  # if untouched by forked child
                tty.tcsetattr(self.writefd, tty.TCSAFLUSH, self._wfd_init_mode)
                if self.debug:
                    log('change wfd back to init mode', f=self.debug)
            # but wait, things here are far more complex than that
            # most applications set mode not by setting it to some value, but by flipping some bits in the flags
            # so, if we set wfd raw mode at the beginning, we are unable to set the correct mode here
            # to solve this situation, set stdin = TTY_RAW, but note that you will need to manually escape control characters by prefixing Ctrl-V

        try:
            rfdlist = [self.readfd, self.STDIN_FILENO]
            if os.isatty(self.writefd):
                # wfd for tty echo
                rfdlist.append(self.writefd)
            while self.isalive():
                if len(rfdlist) == 0: break
                if self.readfd not in rfdlist: break
                try:
                    r, w, e = select_ignore_interrupts(rfdlist, [], [])
                except KeyboardInterrupt:
                    break
                if self.debug: log('r  = ' + repr(r), f=self.debug)
                if self.writefd in r:  # handle tty echo back first if wfd is a tty
                    try:
                        data = os.read(self.writefd, 1024)
                    except OSError as e:
                        if e.errno != errno.EIO:
                            raise
                    if data:
                        if output_filter: data = output_filter(data)
                        # already translated by tty, so don't wrap print_write anymore by default, unless raw_rw set to False
                        stdout(raw_rw and data or self._print_write(data))
                    else:
                        rfdlist.remove(self.writefd)
                if self.readfd in r:
                    try:
                        data = os.read(self.readfd, 1024)
                    except OSError as e:
                        if e.errno != errno.EIO:
                            raise
                    if data:
                        if output_filter: data = output_filter(data)
                        # now we are in interact mode, so users want to see things in real, don't wrap things with print_read here by default, unless raw_rw set to False
                        stdout(raw_rw and data or self._print_read(data))
                    else:
                        rfdlist.remove(self.readfd)
                        self.flag_eof = True
                if self.STDIN_FILENO in r:
                    try:
                        data = os.read(self.STDIN_FILENO, 1024)
                    except OSError as e:
                        # the subprocess may have closed before we get to reading it
                        if e.errno != errno.EIO:
                            raise
                    if self.debug and os.isatty(self.writefd):
                        wfd_mode = tty.tcgetattr(self.writefd)
                        log('stdin wfd mode = ' + repr(wfd_mode), f=self.debug)
                    # in BSD, you can still read '' from rfd, so never use `data is not None` here
                    if data:
                        if input_filter: data = input_filter(data)
                        i = input_filter and -1 or escape_character and data.rfind(escape_character) or -1
                        if i != -1: data = data[:i]
                        if not os.isatty(self.writefd):  # we must do the translation when tty does not help
                            data = data.replace(b'\r', b'\n')
                            # also echo back by ourselves, now we are echoing things we input by hand, so there is no need to wrap with print_write by default, unless raw_rw set to False
                            stdout(raw_rw and data or self._print_write(data))
                        while data != b'' and self.isalive():
                            n = self._write(data)
                            data = data[n:]
                        if i != -1:
                            self.end(force_close=True)
                            break
                    else:
                        self.end(force_close=True)
                        rfdlist.remove(self.STDIN_FILENO)
            while True:  # read the final buffered output, note that the process probably is not alive, so use while True to read until end (fix pipe stdout interact mode bug)
                r, w, e = select_ignore_interrupts([self.readfd], [], [], timeout=self.close_delay)
                if self.readfd in r:
                    try:
                        data = None
                        data = os.read(self.readfd, 1024)
                    except OSError as e:
                        if e.errno != errno.EIO:
                            raise
                    # in BSD, you can still read '' from rfd, so never use `data is not None` here
                    if data:
                        if output_filter: data = output_filter(data)
                        stdout(raw_rw and data or self._print_read(data))
                    else:
                        self.flag_eof = True
                        break
                else:
                    break
        finally:
            if not input_filter and os.isatty(self.STDIN_FILENO):
                tty.tcsetattr(self.STDIN_FILENO, tty.TCSAFLUSH, mode)
            if os.isatty(self.writefd):
                self.ttyraw(self.writefd)

    def isatty(self):
        """This returns True if the file descriptor is open and connected to a
        tty(-like) device, else False. """

        return os.isatty(self.readfd)

    def ttyraw(self, fd, when=tty.TCSAFLUSH, echo=False, raw_in=True, raw_out=False):
        mode = tty.tcgetattr(fd)[:]
        if raw_in:
            mode[tty.IFLAG] = mode[tty.IFLAG] & ~(tty.BRKINT | tty.ICRNL | tty.INPCK | tty.ISTRIP | tty.IXON)
            mode[tty.CFLAG] = mode[tty.CFLAG] & ~(tty.CSIZE | tty.PARENB)
            mode[tty.CFLAG] = mode[tty.CFLAG] | tty.CS8
            if echo:
                mode[tty.LFLAG] = mode[tty.LFLAG] & ~(tty.ICANON | tty.IEXTEN | tty.ISIG)
            else:
                mode[tty.LFLAG] = mode[tty.LFLAG] & ~(tty.ECHO | tty.ICANON | tty.IEXTEN | tty.ISIG)
        if raw_out:
            mode[tty.OFLAG] = mode[tty.OFLAG] & ~(tty.OPOST)
        mode[tty.CC][tty.VMIN] = 1
        mode[tty.CC][tty.VTIME] = 0
        tty.tcsetattr(fd, when, mode)

    def end(self, force_close=False):
        """
        end of writing stream, but we can still read
        """
        if not os.isatty(self.writefd):  # pipes can be closed harmlessly
            os.close(self.writefd)
        # for pty, close master fd in Mac won't cause slave fd input/output error, so let's do it!
        elif platform.system() == 'Darwin':
            os.close(self.writefd)
        else:  # assume Linux here
            # according to http://linux.die.net/man/3/cfmakeraw
            # set min = 0 and time > 0, will cause read timeout and return 0 to indicate EOF
            # but the tricky thing here is, if child read is invoked before this
            # it will still block forever, so you have to call end before that happens
            mode = tty.tcgetattr(self.writefd)[:]
            mode[tty.CC][tty.VMIN] = 0
            mode[tty.CC][tty.VTIME] = 1
            tty.tcsetattr(self.writefd, tty.TCSAFLUSH, mode)
            if force_close:
                time.sleep(self.close_delay)
                os.close(self.writefd)  # might cause EIO (input/output error)! use force_close at your own risk

    def close(self, force=True):
        """
        close and clean up, nothing can and should be done after closing
        """
        if self.closed:
            return
        try:
            os.close(self.writefd)
        except:
            pass  # may already closed in write_eof
        os.close(self.readfd)
        time.sleep(self.close_delay)
        if self.isalive():
            if not self.terminate(force):
                raise Exception('Could not terminate child process')
        self.flag_eof = True
        self.readfd = -1
        self.writefd = -1
        self.closed = True

    def _read(self, size):
        return os.read(self.readfd, size)

    def _write(self, s):
        time.sleep(self.write_delay)
        return os.write(self.writefd, s)

    @property
    def pid(self):
        return self.child_pid


def _is_hostport_tuple(target):
    return isinstance(target, (list, tuple)) and \
           len(target) == 2 and \
           isinstance(target[1], int) and \
           0 <= target[1] < 65536


def zio(target, *, stdin=PIPE, stdout=TTY_RAW, print_read=RAW, print_write=RAW, timeout=8, cwd=None,
        env=None, sighup=signal.SIG_DFL, write_delay=0.05, ignorecase=False, debug=None):
    """
    zio is an easy-to-use io library for pwning development, supporting an unified interface for local process pwning and remote tcp socket io

    example:

    io = zio(('localhost', 80))
    io = zio(socket.create_connection(('127.0.0.1', 80)))
    io = zio('ls -l')
    io = zio(['ls', '-l'])

    params:
        print_read = bool, if true, print all the data read from target
        print_write = bool, if true, print all the data sent out
    """

    if _is_hostport_tuple(target) or isinstance(target, socket.socket):
        return ZioSocket(target, print_read=print_read, print_write=print_write, timeout=timeout,
                         write_delay=write_delay, ignorecase=ignorecase, debug=debug)
    else:
        return ZioProcess(target, stdin=stdin, stdout=stdout, print_read=print_read, print_write=print_write,
                          timeout=timeout, cwd=cwd, env=env, sighup=sighup, write_delay=write_delay,
                          ignorecase=ignorecase, debug=debug)


class Expecter(object):
    def __init__(self, spawn, searcher, searchwindowsize=-1):
        self.spawn = spawn
        self.searcher = searcher
        if searchwindowsize == -1:
            searchwindowsize = spawn.searchwindowsize
        self.searchwindowsize = searchwindowsize

    def new_data(self, data):
        spawn = self.spawn
        searcher = self.searcher

        pos = spawn._buffer.tell()
        spawn._buffer.write(data)

        # determine which chunk of data to search; if a windowsize is
        # specified, this is the *new* data + the preceding <windowsize> bytes
        if self.searchwindowsize:
            spawn._buffer.seek(max(0, pos - self.searchwindowsize))
            window = spawn._buffer.read(self.searchwindowsize + len(data))
        else:
            # otherwise, search the whole buffer (really slow for large datasets)
            window = spawn.buffer
        index = searcher.search(window, len(data))
        if index >= 0:
            value = spawn.buffer
            spawn._buffer = spawn.buffer_type()
            spawn._buffer.write(value[searcher.end:])
            spawn.before = value[: searcher.start]
            spawn.after = value[searcher.start: searcher.end]
            spawn.match = searcher.match
            spawn.match_index = index
            # Found a match
            return index
        elif self.searchwindowsize:
            spawn._buffer = spawn.buffer_type()
            spawn._buffer.write(window)

    def eof(self, err=None):
        spawn = self.spawn

        spawn.before = spawn.buffer
        spawn._buffer = spawn.buffer_type()
        spawn.after = EOF
        index = self.searcher.eof_index
        if index >= 0:
            spawn.match = EOF
            spawn.match_index = index
            return index
        else:
            spawn.match = None
            spawn.match_index = None
            msg = str(spawn)
            msg += '\nsearcher: %s' % self.searcher
            if err is not None:
                msg = str(err) + '\n' + msg
            raise EOF(msg)

    def timeout(self, err=None):
        spawn = self.spawn

        spawn.before = spawn.buffer
        spawn.after = TIMEOUT
        index = self.searcher.timeout_index
        if index >= 0:
            spawn.match = TIMEOUT
            spawn.match_index = index
            return index
        else:
            spawn.match = None
            spawn.match_index = None
            msg = str(spawn)
            msg += '\nsearcher: %s' % self.searcher
            if err is not None:
                msg = str(err) + '\n' + msg
            raise TIMEOUT(msg)

    def errored(self):
        spawn = self.spawn
        spawn.before = spawn.buffer
        spawn.after = None
        spawn.match = None
        spawn.match_index = None

    def expect_loop(self, timeout=-1):
        """Blocking expect"""
        spawn = self.spawn

        if timeout is not None:
            end_time = time.time() + timeout

        try:
            incoming = spawn.buffer
            spawn._buffer = spawn.buffer_type()
            while True:
                idx = self.new_data(incoming)
                # Keep reading until exception or return.
                if idx is not None:
                    return idx
                # No match at this point
                if (timeout is not None) and (timeout < 0):
                    return self.timeout()
                # Still have time left, so read more data
                incoming = spawn.read_nonblocking(spawn.maxread, timeout)
                if self.spawn.delayafterread is not None:
                    time.sleep(self.spawn.delayafterread)
                if timeout is not None:
                    timeout = end_time - time.time()
        except EOF as e:
            return self.eof(e)
        except TIMEOUT as e:
            return self.timeout(e)
        except:
            self.errored()
            raise


# These are copied from pexpect. Thank them.

class searcher_string(object):
    """This is a plain string search helper for the spawn.expect_any() method.
    This helper class is for speed. For more powerful regex patterns
    see the helper class, searcher_re.

    Attributes:

        eof_index     - index of EOF, or -1
        timeout_index - index of TIMEOUT, or -1

    After a successful match by the search() method the following attributes
    are available:

        start - index into the buffer, first byte of match
        end   - index into the buffer, first byte after match
        match - the matching string itself

    """

    def __init__(self, strings):
        """This creates an instance of searcher_string. This argument 'strings'
        may be a list; a sequence of strings; or the EOF or TIMEOUT types. """

        self.eof_index = -1
        self.timeout_index = -1
        self._strings = []
        for n, s in enumerate(strings):
            if s is EOF:
                self.eof_index = n
                continue
            if s is TIMEOUT:
                self.timeout_index = n
                continue
            self._strings.append((n, s))

    def __str__(self):
        """This returns a human-readable string that represents the state of
        the object."""

        ss = [(ns[0], '    %d: "%s"' % ns) for ns in self._strings]
        ss.append((-1, 'searcher_string:'))
        if self.eof_index >= 0:
            ss.append((self.eof_index, '    %d: EOF' % self.eof_index))
        if self.timeout_index >= 0:
            ss.append((self.timeout_index,
                       '    %d: TIMEOUT' % self.timeout_index))
        ss.sort()
        ss = list(zip(*ss))[1]
        return '\n'.join(ss)

    def search(self, buffer, freshlen, searchwindowsize=None):
        """This searches 'buffer' for the first occurrence of one of the search
        strings.  'freshlen' must indicate the number of bytes at the end of
        'buffer' which have not been searched before. It helps to avoid
        searching the same, possibly big, buffer over and over again.

        See class spawn for the 'searchwindowsize' argument.

        If there is a match this returns the index of that string, and sets
        'start', 'end' and 'match'. Otherwise, this returns -1. """

        first_match = None

        # 'freshlen' helps a lot here. Further optimizations could
        # possibly include:
        #
        # using something like the Boyer-Moore Fast String Searching
        # Algorithm; pre-compiling the search through a list of
        # strings into something that can scan the input once to
        # search for all N strings; realize that if we search for
        # ['bar', 'baz'] and the input is '...foo' we need not bother
        # rescanning until we've read three more bytes.
        #
        # Sadly, I don't know enough about this interesting topic. /grahn

        for index, s in self._strings:
            if searchwindowsize is None:
                # the match, if any, can only be in the fresh data,
                # or at the very end of the old data
                offset = -(freshlen + len(s))
            else:
                # better obey searchwindowsize
                offset = -searchwindowsize
            n = buffer.find(s, offset)
            if n >= 0 and (first_match is None or n < first_match):
                first_match = n
                best_index, best_match = index, s
        if first_match is None:
            return -1
        self.match = best_match
        self.start = first_match
        self.end = self.start + len(self.match)
        return best_index


class searcher_re(object):
    """This is regular expression string search helper for the
    spawn.expect_any() method. This helper class is for powerful
    pattern matching. For speed, see the helper class, searcher_string.

    Attributes:

        eof_index     - index of EOF, or -1
        timeout_index - index of TIMEOUT, or -1

    After a successful match by the search() method the following attributes
    are available:

        start - index into the buffer, first byte of match
        end   - index into the buffer, first byte after match
        match - the re.match object returned by a successful re.search

    """

    def __init__(self, patterns):
        """This creates an instance that searches for 'patterns' Where
        'patterns' may be a list or other sequence of compiled regular
        expressions, or the EOF or TIMEOUT types."""

        self.eof_index = -1
        self.timeout_index = -1
        self._searches = []
        for n, s in zip(list(range(len(patterns))), patterns):
            if s is EOF:
                self.eof_index = n
                continue
            if s is TIMEOUT:
                self.timeout_index = n
                continue
            self._searches.append((n, s))

    def __str__(self):
        """This returns a human-readable string that represents the state of
        the object."""

        # ss = [(n, '    %d: re.compile("%s")' %
        #    (n, repr(s.pattern))) for n, s in self._searches]
        ss = list()
        for n, s in self._searches:
            try:
                ss.append((n, '    %d: re.compile("%s")' % (n, s.pattern)))
            except UnicodeEncodeError:
                # for test cases that display __str__ of searches, dont throw
                # another exception just because stdout is ascii-only, using
                # repr()
                ss.append((n, '    %d: re.compile(%r)' % (n, s.pattern)))
        ss.append((-1, 'searcher_re:'))
        if self.eof_index >= 0:
            ss.append((self.eof_index, '    %d: EOF' % self.eof_index))
        if self.timeout_index >= 0:
            ss.append((self.timeout_index, '    %d: TIMEOUT' %
                       self.timeout_index))
        ss.sort()
        ss = list(zip(*ss))[1]
        return '\n'.join(ss)

    def search(self, buffer, freshlen, searchwindowsize=None):
        """This searches 'buffer' for the first occurrence of one of the regular
        expressions. 'freshlen' must indicate the number of bytes at the end of
        'buffer' which have not been searched before.

        See class spawn for the 'searchwindowsize' argument.

        If there is a match this returns the index of that string, and sets
        'start', 'end' and 'match'. Otherwise, returns -1."""

        first_match = None
        # 'freshlen' doesn't help here -- we cannot predict the
        # length of a match, and the re module provides no help.
        if searchwindowsize is None:
            searchstart = 0
        else:
            searchstart = max(0, len(buffer) - searchwindowsize)
        for index, s in self._searches:
            match = s.search(buffer, searchstart)
            if match is None:
                continue
            n = match.start()
            if first_match is None or n < first_match:
                first_match = n
                the_match = match
                best_index = index
        if first_match is None:
            return -1
        self.start = first_match
        self.match = the_match
        self.end = self.match.end()
        return best_index


def is_executable_file(path):
    """Checks that path is an executable regular file, or a symlink towards one.

    This is roughly ``os.path isfile(path) and os.access(path, os.X_OK)``.
    """
    # follow symlinks,
    fpath = os.path.realpath(path)

    if not os.path.isfile(fpath):
        # non-files (directories, fifo, etc.)
        return False

    mode = os.stat(fpath).st_mode

    if (sys.platform.startswith('sunos')
            and os.getuid() == 0):
        # When root on Solaris, os.X_OK is True for *all* files, irregardless
        # of their executability -- instead, any permission bit of any user,
        # group, or other is fine enough.
        #
        # (This may be true for other "Unix98" OS's such as HP-UX and AIX)
        return bool(mode & (stat.S_IXUSR |
                            stat.S_IXGRP |
                            stat.S_IXOTH))

    return os.access(fpath, os.X_OK)


def which(filename, env=None):
    """This takes a given filename; tries to find it in the environment path;
    then checks if it is executable. This returns the full path to the filename
    if found and executable. Otherwise this returns None."""

    # Special case where filename contains an explicit path.
    if os.path.dirname(filename) != '' and is_executable_file(filename):
        return filename
    if env is None:
        env = os.environ
    p = env.get('PATH')
    if not p:
        p = os.defpath
    pathlist = p.split(os.pathsep)
    for path in pathlist:
        ff = os.path.join(path, filename)
        if is_executable_file(ff):
            return ff
    return None


def split_command_line(command_line):
    """This splits a command line into a list of arguments. It splits arguments
    on spaces, but handles embedded quotes, doublequotes, and escaped
    characters. It's impossible to do this with a regular expression, so I
    wrote a little state machine to parse the command line. """

    arg_list = []
    arg = ''

    # Constants to name the states we can be in.
    state_basic = 0
    state_esc = 1
    state_singlequote = 2
    state_doublequote = 3
    # The state when consuming whitespace between commands.
    state_whitespace = 4
    state = state_basic

    for c in command_line:
        if state == state_basic or state == state_whitespace:
            if c == '\\':
                # Escape the next character
                state = state_esc
            elif c == r"'":
                # Handle single quote
                state = state_singlequote
            elif c == r'"':
                # Handle double quote
                state = state_doublequote
            elif c.isspace():
                # Add arg to arg_list if we aren't in the middle of whitespace.
                if state == state_whitespace:
                    # Do nothing.
                    pass
                else:
                    arg_list.append(arg)
                    arg = ''
                    state = state_whitespace
            else:
                arg = arg + c
                state = state_basic
        elif state == state_esc:
            arg = arg + c
            state = state_basic
        elif state == state_singlequote:
            if c == r"'":
                state = state_basic
            else:
                arg = arg + c
        elif state == state_doublequote:
            if c == r'"':
                state = state_basic
            else:
                arg = arg + c

    if arg != '':
        arg_list.append(arg)
    return arg_list


def select_ignore_interrupts(iwtd, owtd, ewtd, timeout=None):
    """This is a wrapper around select.select() that ignores signals. If
    select.select raises a select.error exception and errno is an EINTR
    error then it is ignored. Mainly this is used to ignore sigwinch
    (terminal resize). """

    # if select() is interrupted by a signal (errno==EINTR) then
    # we loop back and enter the select() again.
    if timeout is not None:
        end_time = time.time() + timeout
    while True:
        try:
            return select.select(iwtd, owtd, ewtd, timeout)
        except InterruptedError:
            err = sys.exc_info()[1]
            if err.args[0] == errno.EINTR:
                # if we loop back we have to subtract the
                # amount of time we already waited.
                if timeout is not None:
                    timeout = end_time - time.time()
                    if timeout < 0:
                        return ([], [], [])
            else:
                # something else caused the select.error, so
                # this actually is an exception.
                raise


def all_pids():
    return [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='[zio] is an easy-to-use io library for pwning development, '
                    'supporting an unified interface for local process pwning and TCP socket io.')

    parser.add_argument('-i', '--stdin', help='tty|pipe, specify tty or pipe stdin, default to tty')
    parser.add_argument('-o', '--stdout', help='tty|pipe, specify tty or pipe stdout, default to tty')
    parser.add_argument('-t', '--timeout', type=int, help='integer seconds, specify timeout')
    parser.add_argument('-r', '--read',
                        help='how to print out content read from child process, may be RAW(True), NONE(False), REPR, HEX')
    parser.add_argument('-w', '--write',
                        help='how to print out content written to child process, may be RAW(True), NONE(False), REPR, HEX')
    parser.add_argument('-a', '--ahead', help='message to feed into stdin before interact')
    parser.add_argument('-b', '--before', help="don't do anything before reading those input")
    parser.add_argument('-d', '--decode',
                        help='when in interact mode, this option can be used to specify decode function REPR/HEX to input raw hex bytes')
    parser.add_argument('-l', '--delay', help='write delay, time to wait before write')
    parser.add_argument('--debug', help='debug mode')
    parser.add_argument('target', help='cmdline | host port', nargs=argparse.ONE_OR_MORE)

    args = parser.parse_args()

    decode = None
    ahead = None
    before = None

    kwargs = {
        'stdin': TTY,  # don't use tty_raw now let's say few people use raw tty in the terminal by hand
        'stdout': TTY,
    }

    if args.stdin:
        if args.stdin.lower() == TTY.lower():
            kwargs['stdin'] = TTY
        elif args.stdin.lower() == TTY_RAW.lower():
            kwargs['stdin'] = TTY_RAW
        else:
            kwargs['stdin'] = PIPE

    if args.stdout:
        if args.stdout.lower() == TTY.lower():
            kwargs['stdout'] = TTY
        elif args.stdout.lower() == TTY_RAW.lower():
            kwargs['stdout'] = TTY_RAW
        else:
            kwargs['stdout'] = PIPE

    if args.timeout:
        kwargs['timeout'] = args.timeout

    if args.read:
        a = args.read
        if a.lower() == 'hex':
            kwargs['print_read'] = COLORED(HEX, 'yellow')
        elif a.lower() == 'repr':
            kwargs['print_read'] = COLORED(REPR, 'yellow')
        elif a.lower() == 'none':
            kwargs['print_read'] = NONE
        else:
            kwargs['print_read'] = RAW

    if args.write:
        a = args.write
        if a.lower() == 'hex':
            kwargs['print_write'] = COLORED(HEX, 'cyan')
        elif a.lower() == 'repr':
            kwargs['print_write'] = COLORED(REPR, 'cyan')
        elif a.lower() == 'none':
            kwargs['print_write'] = NONE
        else:
            kwargs['print_write'] = RAW

    if args.decode:
        a = args.decode
        if a.lower() == 'eval':
            decode = EVAL
        elif a.lower() == 'unhex':
            decode = UNHEX

    if args.ahead:
        ahead = args.ahead
    if args.before:
        before = args.before

    if args.debug:
        kwargs['debug'] = open(args.debug, 'wt')

    if args.delay:
        kwargs['write_delay'] = args.delay

    target = None

    if len(args.target) == 2:
        try:
            port = int(args.target[1])
            if _is_hostport_tuple((args.target[0], port)):
                target = (args.target[0], port)
        except:
            pass
    if not target:
        if len(args.target) == 1:
            target = args.target[0]
        else:
            target = args.target

    io = zio(target, **kwargs)
    if before:
        io.read_until(before)
    if ahead:
        io.write(ahead)
    io.interact(input_filter=decode, raw_rw=False)


if __name__ == '__main__':
    main()

# vi:set et ts=4 sw=4 ft=python :
