#!/bin/sh

cd ..
for TESTDATA in test/data/*; do
	TEST=`basename ${TESTDATA}`
	make test/${TEST} || exit 1
	for IN in ${TESTDATA}/*.in; do
		./test/${TEST} ${IN} > ${IN}.got 2>&1
		OUT=`echo ${IN} | awk '{ print substr($0, 0, length($0) - 3); }'`.out
		diff -u "${OUT}" "${IN}.got" && rm "${IN}.got" || echo "FAILED ${IN}"
	done
done

FAILED=`find test -name \*.in.got | wc -l`
[ "${FAILED}" -gt 0 ] && exit 1
echo "PASSED" && exit 0
