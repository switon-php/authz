<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Fixtures\PermissionScanner;

use Attribute;
use Switon\Routing\Attribute\MappingInterface;

#[Attribute(Attribute::TARGET_METHOD)]
class GetMapping implements MappingInterface
{
    public function __construct(public string $path)
    {
    }

    public function getPath(): string|array|null
    {
        return $this->path;
    }

    public function getVerb(): string
    {
        return 'GET';
    }
}
