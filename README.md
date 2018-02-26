fit-aligner
===========

A tool to align specific image blobs in a FIT file for
fast reading using U-boot fsfitxtract.

Alignment is required to use DMA instead of software copying.

It adds FDT\_NOP words before prop descriptions to align
it to specific value (512 for reading from FAT on USB stick).

Requirements
------------

 * libfdt

Build
-----

```
$ make
```

Launch
------

```
$ ./fit_aligner -i input.fit -o output.fit -a 512
```

TODO
----

 * Cleaning up
