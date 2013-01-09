all-local: stamp-examples

stamp-examples: $(wildcard *.conf) $(wildcard *.stmnt) example-xml.sh         \
                ../../../test/modules/processor/pattern/patterndb.xml         \
                ../../../test/modules/extension/multiline/xm_multiline1.conf  \
                ../../../test/modules/extension/multiline/xm_multiline1.in    \
                ../../../test/modules/extension/multiline/xm_multiline1.out   \
                ../../../test/modules/extension/multiline/xm_multiline2.conf  \
                ../../../test/modules/extension/multiline/xm_multiline2.in    \
                ../../../test/modules/extension/multiline/xm_multiline2.out   \
                ../../../test/modules/extension/multiline/xm_multiline3.conf  \
                ../../../test/modules/extension/multiline/xm_multiline3.in    \
                ../../../test/modules/extension/multiline/xm_multiline3.out   \
                ../../../test/modules/extension/multiline/xm_multiline4.conf  \
                ../../../test/modules/extension/multiline/xm_multiline4.in    \
                ../../../test/modules/extension/multiline/xm_multiline4.out   \
                ../../../test/modules/extension/perl/xm_perl.conf             \
                ../../../test/modules/extension/perl/processlogs.pl

	-./example-xml.sh && touch stamp-examples

maintainer-clean-local:
	-$(RM) $(wildcard *.xml) stamp-examples

dist-hook:
	cp $(top_srcdir)/doc/reference-manual/config-examples/*.xml $(distdir)/

EXTRA_DIST = $(wildcard *.xml) $(wildcard *.conf) $(wildcard *.stmnt) stamp-examples example-xml.sh example-tester.sh
