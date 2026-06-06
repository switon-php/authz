<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\AuthorizationInterface;
use Switon\Authorizing\ServiceProvider;
use Switon\Core\ContainerInterface;
use Switon\Eventing\ListenerProviderInterface;
use Switon\Authorizing\Tests\TestCase;

class ServiceProviderTest extends TestCase
{
    public function testRegisterDoesNothing(): void
    {
        $container = $this->createMock(ContainerInterface::class);
        $container->expects($this->never())->method('set');

        $provider = new ServiceProvider();
        $provider->register($container);

        $this->assertTrue(true);
    }

    public function testBootRegistersAuthorizationListener(): void
    {
        $listenerProvider = $this->createMock(ListenerProviderInterface::class);
        $listenerProvider->expects($this->once())
            ->method('register')
            ->with(AuthorizationInterface::class);

        /** @var ServiceProvider $provider */
        $provider = $this->make(ServiceProvider::class, [
            'listenerProvider' => $listenerProvider,
        ]);

        $provider->boot();
    }
}
