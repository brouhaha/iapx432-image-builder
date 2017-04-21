# iapx432-image-builder - Build iAPX 432 executable image from XML description

Copyright 2014, 2015, 2016, 2017 Eric Smith <spacewar@gmail.com>

iapx432-image-builder development is hosted at the
[iapx432-image-builder Github repository](https://github.com/brouhaha/iapx432-image-builder/).

## Introduction

Introduced in 1981, the iAPX 432 was Intel's first 32-bit
microprocessor family, which was not in any way related to the x86.
An iAPX 432 system typically contained two kinds of processors:

* General Data Processor (GDP), consisting of the 43201 Instruction
  Unit and 43202 Execution Unit

* Attached Processor subsystems, consisting of the 43203 Interface
  Processor (IP) and an 8-bit or 16-bit general-purpose
  microprocessors, the Attached Processor (AP), such as an 8085, 8086,
  or 8088.

The iAPX 432 system hardware and microcode implemented an
object-oriented capability-based computer architecture, where all
software-accessible memory was organized as objects, some with
architecture-defined semantics.  A software process was only able to
access objects for which it had a suitable Access Descriptor (AD); it
was not possible to refer to memory by an address as used in
conventional CPU architectures.

Intel offered two programming languages for the iAPX 432.

* Ada 83 was intended to be the primary language for iAPX 432 software
  development.

* Object Programming Language (OPL-432), a dialect of Smalltalk, which
  was only supported on the iSBC 432/100 evaluation board using
  the Release 1 GDP.

Because of the lack of publicly available iAPX 432 development
software, iapx432-image-builder is being developed to support creation
of executable memory images for use with the iAPX 432 Release 1 GDP.
iapx432-image-builder accepts an input an XML description of the
necessary objects, including instruction objects specified at
assembly-language level, and produces a binary memory image for
execution on an iAPX 432 system.

Presently only Release 1 of the iAPX 432 architecture is supported,
although some preliminary work on the Release 3.2 architecture
specification has been done.

## Status

iapx432-image-builder is under development, but is incomplete and
untested.  It is NOT at this time expected to yield valid executable
images.

## Usage

The iapx432-image-builder is invoked from the command line,
providing arguments for the image description XML input file,
and the binary image output file:

* `builder image.xml image.bin`

## License information

This program is free software: you can redistribute it and/or modify
it under the terms of version 3 of the GNU General Public License
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
