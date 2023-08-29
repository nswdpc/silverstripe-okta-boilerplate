<?php

namespace NSWDPC\Authentication\Okta;

use Cache\Adapter\Void\VoidCachePool;
use League\Flysystem\Adapter\AbstractAdapter;
use Okta\Cache\MemoryManager;

/**
 * Extend Okta MemoryManager to provide VoidCachePool
 */
class VoidCacheManager extends MemoryManager
{
    public function __construct(AbstractAdapter $adapter = null)
    {

        $this->setCachePool(
            new VoidCachePool()
        );

    }
}
