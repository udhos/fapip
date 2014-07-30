INTRODUCTION
============

        fapip stands for fasp ping probe, a tool for measuring packet
        loss against a remote host.

LICENSE
=======

	fapip - fast ping probe
        Copyright (C) 2009 Everton da Silva Marques

        fapip is free software; you can redistribute it and/or modify
        it under the terms of the GNU General Public License as
        published by the Free Software Foundation; either version 2,
        or (at your option) any later version.

        fapip is distributed in the hope that it will be useful, but
        WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public
        License along with fapip; see the file COPYING.  If not, write
        to the Free Software Foundation, Inc., 59 Temple Place - Suite
        330, Boston, MA 02111-1307, USA.

HOME
====

        fapip lives at https://github.com/udhos/fapip

BUILDING
========

        Then type:

        $ cd src
        $ make

        Afterwards copy the 'fapip' binary to your system's proper
        filesystem location. For instance:

        $ sudo cp fapip /usr/local/bin

	Please notice it requires root privileges, so you may
	optionally:

        $ sudo chmod u+s /usr/local/bin/fapip

BASIC USAGE
===========

        Starting against host located at 1.1.1.1:

        $ fapip 1.1.1.1

        Display brief help about command line options:

        $ fapip -h


END
===

