<?php
// Minimal .env loader (no external package required)
if (!function_exists('loadEnv')) {
    function loadEnv($path) {
        static $loaded = [];

        if (isset($loaded[$path])) {
            return;
        }

        if (!is_readable($path)) {
            $loaded[$path] = true;
            return;
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            $loaded[$path] = true;
            return;
        }

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $separator = strpos($line, '=');
            if ($separator === false) {
                continue;
            }

            $name = trim(substr($line, 0, $separator));
            $value = trim(substr($line, $separator + 1));

            if ($name === '') {
                continue;
            }

            // Remove surrounding quotes if present.
            if (strlen($value) >= 2) {
                $first = $value[0];
                $last = $value[strlen($value) - 1];
                if (($first === '"' && $last === '"') || ($first === "'" && $last === "'")) {
                    $value = substr($value, 1, -1);
                }
            }

            if (getenv($name) === false) {
                putenv($name . '=' . $value);
            }

            if (!isset($_ENV[$name])) {
                $_ENV[$name] = $value;
            }

            if (!isset($_SERVER[$name])) {
                $_SERVER[$name] = $value;
            }
        }

        $loaded[$path] = true;
    }
}

if (!function_exists('env')) {
    function env($key, $default = null) {
        $value = getenv($key);
        if ($value === false) {
            if (isset($_ENV[$key])) {
                return $_ENV[$key];
            }
            if (isset($_SERVER[$key])) {
                return $_SERVER[$key];
            }
            return $default;
        }

        return $value;
    }
}

loadEnv(__DIR__ . DIRECTORY_SEPARATOR . '.env');
