#!/bin/sh

#libcutil
cp ../libc-linux/*.h include/cutil/
cp ../libc-linux/libcutil.a lib/

#liboci
cp ../liboci/*.h include/oci/
cp ../liboci/liboci.a lib/

#libexp
cp ../libexp/*.h include/exp/
cp ../libexp/libexp.a lib/

#libsql
cp ../libsql/*.h include/sql/
cp ../libsql/libsql.a lib/

#libnet
cp ../libnet/*.h include/net/
cp ../libnet/libnet.a lib/

make clean
make
