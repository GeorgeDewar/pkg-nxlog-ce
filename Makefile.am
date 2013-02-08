SUBDIRS	= src test doc

maintainer-clean-local:
	-$(RM) aclocal.m4 configure config.h stamp-h1
	-$(RM) config.guess config.sub depcomp install-sh missing mkinstalldirs compile ltmain.sh ylwrap

changelog_DATA = ChangeLog.txt
changelogdir = $(docdir)

EXTRA_DIST = autogen.sh libtool svn_version.txt version.sh VERSION $(changelog_DATA) LICENSE $(wildcard parsers/*.conf) \
	     $(wildcard packaging/debian/*.pem) \
	     packaging/debian/changelog \
	     packaging/debian/compat \
	     packaging/debian/control \
	     packaging/debian/copyright \
	     packaging/debian/nxlog.init \
	     packaging/debian/make_debs.sh \
	     packaging/debian/nxlog.conf \
	     packaging/debian/nxlog-ce.install \
	     packaging/debian/watch \
	     packaging/debian/postinst \
	     packaging/debian/postrm \
	     packaging/debian/rules \
	     packaging/debian/source/format \
	     packaging/windows/license.rtf \
	     packaging/windows/nxlog.conf \
	     packaging/windows/nxlog.wxs \
	     packaging/windows/nx_logo.ico \
	     packaging/windows/bannrbmp.bmp \
	     packaging/windows/dlgbmp.bmp \
	     packaging/windows/pkgmsi.sh \
	     packaging/windows/README.txt \
	     packaging/windows/wininst.sh \
	     packaging/redhat/nxlog.spec \
	     packaging/redhat/nxlog.conf \
	     packaging/redhat/init \
	     packaging/redhat/make_rpm.sh
