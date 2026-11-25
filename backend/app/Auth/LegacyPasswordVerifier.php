<?php

namespace App\Auth;

use FFI;

/** Reads Werkzeug hashes once; Laravel replaces them with bcrypt on login. */
class LegacyPasswordVerifier
{
    public static function isLegacy(string $hash): bool
    {
        return str_starts_with($hash, 'scrypt:') || str_starts_with($hash, 'pbkdf2:');
    }

    public function verify(string $password, string $hash): bool
    {
        $parts = explode('$', $hash);
        if (count($parts) !== 3 || ! ctype_xdigit($parts[2])) {
            return false;
        }
        [$method, $salt, $expected] = $parts;
        $params = explode(':', $method);
        if ($params[0] === 'pbkdf2' && count($params) === 3 && $params[1] === 'sha256') {
            $rounds = (int) $params[2];

            return $rounds > 0 && $rounds <= 2000000
                && hash_equals($expected, hash_pbkdf2('sha256', $password, $salt, $rounds, strlen($expected)));
        }
        if ($params[0] !== 'scrypt' || count($params) !== 4 || strlen($expected) !== 128) {
            return false;
        }
        [$n, $r, $p] = array_map('intval', array_slice($params, 1));
        if ($n < 2 || $n > 262144 || ($n & ($n - 1)) !== 0 || $r < 1 || $r > 16 || $p < 1 || $p > 4) {
            return false;
        }
        // OpenSSL's scrypt uses the same byte format as Werkzeug, including its short salt.
        $crypto = FFI::cdef('int EVP_PBE_scrypt(const char *pass, size_t passlen,
            const unsigned char *salt, size_t saltlen, uint64_t N, uint64_t r,
            uint64_t p, uint64_t maxmem, unsigned char *key, size_t keylen);', 'libcrypto.so.3');
        $saltBytes = $crypto->new('unsigned char['.max(1, strlen($salt)).']');
        FFI::memcpy($saltBytes, $salt, strlen($salt));
        $key = $crypto->new('unsigned char[64]');
        $ok = $crypto->EVP_PBE_scrypt($password, strlen($password), $saltBytes, strlen($salt), $n, $r, $p, 536870912, $key, 64);

        return $ok === 1 && hash_equals($expected, bin2hex(FFI::string($key, 64)));
    }
}
