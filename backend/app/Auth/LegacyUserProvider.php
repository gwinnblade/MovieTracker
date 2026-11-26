<?php

namespace App\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;

class LegacyUserProvider extends EloquentUserProvider
{
    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        $hash = $user->getAuthPassword();
        if (LegacyPasswordVerifier::isLegacy($hash ?? '')) {
            return isset($credentials['password'])
                && app(LegacyPasswordVerifier::class)->verify($credentials['password'], $hash);
        }

        return parent::validateCredentials($user, $credentials);
    }

    public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void
    {
        if (LegacyPasswordVerifier::isLegacy($user->getAuthPassword() ?? '')) {
            $user->forceFill([$user->getAuthPasswordName() => $this->hasher->make($credentials['password'])])->save();

            return;
        }
        parent::rehashPasswordIfRequired($user, $credentials, $force);
    }
}
