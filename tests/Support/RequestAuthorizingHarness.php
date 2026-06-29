<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Support;

use ReflectionMethod;
use Switon\Http\Event\RequestAuthorizing;
use Switon\Http\RequestHandlerInterface;

/**
 * Builds {@see RequestAuthorizing} from controller/action names (reflection only here).
 */
final class RequestAuthorizingHarness
{
    public static function forAction(
        RequestHandlerInterface $handler,
        object|string $controller,
        string $method,
    ): RequestAuthorizing {
        return new RequestAuthorizing($handler, new ReflectionMethod($controller, $method));
    }
}
