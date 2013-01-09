#!/bin/sh

DEBDIR="../../debian"
(
    VERSION=`cd ../.. && ./version.sh|sed s/\:/_/`
    
#    if echo $VERSION | grep \: >/dev/null; then
#	echo "refusing to build package, changes must be committed to svn first"
#	exit 1
#    fi
    RELEASE_DATE=`LC_ALL=en_US date "+%a, %d %b %Y %T %z"`
    mv changelog changelog.org
    echo "nxlog-ce ($VERSION) unstable; urgency=low" >changelog
    echo "" >>changelog
    echo "  * SVN snapshot release." >>changelog
    echo "" >>changelog
    echo " -- Botond Botyanszki <boti@nxlog.org>  $RELEASE_DATE" >>changelog
    echo "" >>changelog
    cat changelog.org >>changelog

    cd ../..
    ln -s -f packaging/debian debian
#    export DEB_BUILD_OPTIONS=nostrip,noopt
    dpkg-buildpackage -b -rfakeroot || exit 2;
    if test "x$RUN_TESTS" = "x1";
	then make check || exit 2;
    fi
)
RC=$?
rm -f $DEBDIR
if test -f changelog.org; then
    rm -f changelog
    mv changelog.org changelog
fi
exit $RC
