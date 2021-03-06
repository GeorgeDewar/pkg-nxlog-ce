#!/bin/sh
PROCESSOR=../../../src/utils/nxlog-processor
STMNT_VERIFIER="../../../src/utils/nxlog-stmnt-verifier --moduledir=../../../src/modules"
ERRLOG=err.log

for i in *.conf; do
    $PROCESSOR -v -c $i 2>$ERRLOG 1>/dev/null;
    if test $? != 0; then
	echo "Example config file $i is invalid, see $ERRLOG";
	cat $ERRLOG
	exit 1;
    fi
    rm -f $ERRLOG
done

for i in *.stmnt; do
    $STMNT_VERIFIER < $i 2>$ERRLOG 1>/dev/null;
    if test $? != 0; then
	echo "Example statement file $i is invalid, see $ERRLOG";
	cat $ERRLOG
	exit 1;
    fi
    rm -f $ERRLOG
done
