<?php

declare(strict_types=1);

namespace Switon\Authorizing\Tests\Unit;

use Switon\Authorizing\Lookup;
use Switon\Authorizing\Tests\TestCase;

class LookupTest extends TestCase
{
    /**
     * {@see \Switon\Authorizing\Lookup} uses the config array as an exact string key map only; values are opaque CSV.
     */
    public function testGetPermissionsReturnsConfiguredCsvByExactRoleKey(): void
    {
        /** @var Lookup $lookup */
        $lookup = $this->make(Lookup::class, [
            'permissions' => [
                'reader' => 'post::index',
                'editor' => 'post::index,post::edit',
            ],
        ]);

        $this->assertSame('post::index', $lookup->getPermissions('reader'));
        $this->assertSame('post::index,post::edit', $lookup->getPermissions('editor'));
    }

    /**
     * Keys are not normalized: different casing or absent keys yield null like any PHP array lookup.
     */
    public function testGetPermissionsReturnsNullForUnknownOrCaseMismatchedRole(): void
    {
        /** @var Lookup $lookup */
        $lookup = $this->make(Lookup::class, [
            'permissions' => [
                'Editor' => 'post::edit',
            ],
        ]);

        $this->assertNull($lookup->getPermissions('editor'));
        $this->assertNull($lookup->getPermissions('moderator'));
    }
}
