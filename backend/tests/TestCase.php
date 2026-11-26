<?php

namespace Tests;

use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    public function createApplication()
    {
        $app = parent::createApplication();
        // Docker passes DB_DATABASE as a server variable. Override it before
        // RefreshDatabase runs; tests must never migrate the mounted database.
        $app['config']->set([
            'database.default' => 'sqlite', 'database.connections.sqlite.database' => ':memory:',
            'cache.default' => 'array', 'session.driver' => 'array', 'mail.default' => 'array',
            'services.tmdb.api_key' => 'test-token',
            'sanctum.stateful' => ['localhost:3002', '127.0.0.1:3002'],
        ]);
        $app['db']->purge('sqlite');

        return $app;
    }
}
