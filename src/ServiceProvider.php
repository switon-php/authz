<?php

declare(strict_types=1);

namespace Switon\Authorizing;

use Switon\Core\Attribute\Autowired;
use Switon\Core\ContainerInterface;
use Switon\Core\ServiceProviderInterface;
use Switon\Eventing\ListenerProviderInterface;

/**
 * Registers authorization listeners for framework bootstrap.
 *
 * Guidance: Authorization stays auto-mapped by interface; this provider exists to attach its HTTP event listener during boot.
 *
 * @see \Switon\Core\ServiceProviderInterface
 * @see \Switon\Authorizing\AuthorizationInterface
 * @see \Switon\Eventing\ListenerProviderInterface
 */
class ServiceProvider implements ServiceProviderInterface
{
    #[Autowired] protected ListenerProviderInterface $listenerProvider;

    /** {@inheritDoc} */
    public function register(ContainerInterface $container): void
    {
    }

    /** {@inheritDoc} */
    public function boot(): void
    {
        $this->listenerProvider->register(AuthorizationInterface::class);
    }
}
