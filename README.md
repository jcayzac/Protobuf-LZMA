Protobuf-LZMA
=============

    (C) 2011, Tonchidot Corporation.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

     * Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in
       the documentation and/or other materials provided with the distribution.
     * Neither the name of the Tonchidot Corporation nor the names of its
       contributors may be used to endorse or promote products derived from
       this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
    THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Implements two classes for using with the open-source [Protobuf](http://code.google.com/p/protobuf/) C++ library, LzmaInputStream and LzmaOutputStream, that compress and decompress data using [Igor Pavlov's public domain LZMA SDK](http://www.7-zip.org/sdk.html). Achieved compression ratio is often twice as good as with GZip compression.

Compression is done per block of data (1MB by default, but it's configurable). Each block embeds a SHA-256 digest of the uncompressed data, so that it can be verified at decompression time. Such verification is entirely optional.

Compression settings, such as dictionary size or compression level, can be modified anytime and will affect the subsequent blocks.

This code is hereby released under New BSD license.

Limitations:
------------

I'm using these classes for reading from and writing to local files with std::ifstream and std::ofstream, so there might be some problems when an entire block of data cannot be read or written at once. If you want to use them for I/O over a network connection, feel free to fix this issue and send me a pull request :)

Building the LZMA SDK:
----------------------

Refer to its documentation. All you need if you want to encode using a single CPU core is *LzFind.c*, *LzmaDec.c*, *LzmaEnc.c* and *Sha256.c*. You will also need to append *-D_7ZIP_ST* (as in "Single Thread") to your CFLAGS.
