/*
 * This file is part of the nxlog log collector tool.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 * License:
 * Copyright (C) 2012 by Botond Botyanszki
 * This library is free software; you can redistribute it and/or modify
 * it under the same terms as Perl itself, either Perl version 5.8.5 or,
 * at your option, any later version of Perl 5 you may have available.
 */

#ifndef __NX_XM_PERL_H
#define __NX_XM_PERL_H

#include "../../../common/types.h"
#include <EXTERN.h>
#include <perl.h>

typedef struct nx_xm_perl_conf_t
{
    const char * perlcode;
    PerlInterpreter *perl_interpreter;
} nx_xm_perl_conf_t;

PerlInterpreter *nx_xm_perl_init();
void nx_xm_perl_destroy();

#endif	/* __NX_XM_PERL_H */
