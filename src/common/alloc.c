/*
 * This file is part of the nxlog log collector tool.
 * See the file LICENSE in the source root for licensing terms.
 * Website: http://nxlog.org
 * Author: Botond Botyanszki <botond.botyanszki@nxlog.org>
 */

#include "types.h"
#include "exception.h"
#include "alloc.h"


#define NX_LOGMODULE NX_LOGMODULE_CORE


apr_pool_t *nx_pool_create_child(apr_pool_t *parent)
{
    apr_pool_t *pool;
    apr_allocator_t *allocator;

    CHECKERR(apr_pool_create(&pool, parent));
    if ( parent == NULL )
    {
	allocator = apr_pool_allocator_get(pool);
	ASSERT(allocator != NULL);
	apr_allocator_max_free_set(allocator, NX_MAX_ALLOCATOR_SIZE);
    }

    return ( pool );
}



apr_pool_t *nx_pool_create_core()
{
    apr_pool_t *pool;
    apr_allocator_t *allocator;

    CHECKERR(apr_allocator_create(&allocator));
    CHECKERR(apr_pool_create_ex(&pool, NULL, NULL, allocator));
    allocator = apr_pool_allocator_get(pool);
    apr_allocator_owner_set(allocator, pool);
    ASSERT(allocator != NULL);
    apr_allocator_max_free_set(allocator, NX_MAX_ALLOCATOR_SIZE);

    return ( pool );
}
