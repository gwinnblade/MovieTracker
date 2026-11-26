<?php

namespace Tests\Unit;

use App\Auth\LegacyPasswordVerifier;
use PHPUnit\Framework\TestCase;

class LegacyPasswordTest extends TestCase
{
    public const HASH = 'scrypt:32768:8:1$VectorSalt2026$30abc289fcbab0bd317d7bf450e43871dec86c891c94a33e27c9e7b361572993495fe9f8600bad28f5ce3441505325e8652a0507e2f273f7a3c91bb0b000cdc6';

    public function test_werkzeug_scrypt_known_vector_and_wrong_password(): void
    {
        $verifier = new LegacyPasswordVerifier;
        $this->assertTrue($verifier->verify('TestPassword2026!', self::HASH));
        $this->assertFalse($verifier->verify('wrong-password', self::HASH));
    }

    public function test_malformed_or_excessive_parameters_are_rejected(): void
    {
        $verifier = new LegacyPasswordVerifier;
        $this->assertFalse($verifier->verify('anything', 'scrypt:999999999:8:1$salt$'.str_repeat('a', 128)));
        $this->assertFalse($verifier->verify('anything', 'scrypt:32768:8:1$invalid'));
        $this->assertFalse($verifier->verify('anything', 'pbkdf2:sha256:0$salt$aa'));
    }
}
