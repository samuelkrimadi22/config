<?php
// ============================================================
// Clipora - Konfigurasi Global (FIXED VERSION V10.0.0)
// ============================================================

// 1. Matikan output buffering issue - WAJIB paling atas
// Ini mencegah "headers already sent" error
if (ob_get_level() === 0) {
    ob_start();
}

// 2. Load .env file
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value, " \t\n\r\0\x0B\"'");
        if (!getenv($key)) {
            putenv("$key=$value");
            $_ENV[$key] = $value;
        }
    }
}

// 3. Environment Config
define('APP_ENV', getenv('APP_ENV') ?: 'development');
define('BASE_URL', 'http://38.103.170.165:3000');
define('API_URL', 'http://38.103.170.165:3000/api');

define('APP_NAME', 'Clipora');
define('APP_VERSION', 'V1.0.0');
define('APP_TAGLINE', '');
define('MAX_FILE_SIZE', 500 * 1024 * 1024);

// 4. Midtrans Config
define('MIDTRANS_MODE', getenv('MIDTRANS_MODE') ?: 'sandbox');
define('MIDTRANS_MERCHANT_ID', getenv('MIDTRANS_MERCHANT_ID') ?: '');
define('MIDTRANS_CLIENT_KEY', getenv('MIDTRANS_CLIENT_KEY') ?: '');
define('MIDTRANS_SERVER_KEY', getenv('MIDTRANS_SERVER_KEY') ?: '');
define('MIDTRANS_SNAP_URL', MIDTRANS_MODE === 'production'
    ? 'https://app.midtrans.com/snap/snap.js'
    : 'https://app.sandbox.midtrans.com/snap/snap.js');

// 5. Cookie Config
define('COOKIE_TOKEN', 'clipora_token');
define('COOKIE_USERNAME', 'clipora_username');
define('COOKIE_PLAN', 'clipora_plan');
define('COOKIE_ADMIN', 'clipora_is_admin');
define('COOKIE_EXPIRE', 7 * 24 * 3600); // 7 hari
define('SESSION_LIFETIME', 4 * 3600);   // 4 jam

// 6. Session Start - DENGAN PENGAMAN
if (session_status() === PHP_SESSION_NONE) {
    // Cek apakah headers sudah dikirim
    if (headers_sent($file, $line)) {
        error_log("[SESSION] Headers already sent at $file:$line - skip session_start");
    } else {
        $isProduction = (APP_ENV === 'production');

        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path' => '/',
            'domain' => '',
            'secure' => $isProduction,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);

        ini_set('session.gc_maxlifetime', SESSION_LIFETIME);
        ini_set('session.gc_probability', 1);
        ini_set('session.gc_divisor', 100);

        session_start();

        // Google OAuth Token Handler
        if (isset($_GET['token']) && isset($_GET['login']) && $_GET['login'] === 'google') {
            $googleToken = $_GET['token'];
            
            $_SESSION['clipora_token'] = $googleToken;
            $_SESSION['login_method'] = 'google';
            $_SESSION['user_logged_in'] = true;
            
            try {
                $parts = explode('.', $googleToken);
                if (count($parts) === 3) {
                    $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                    if ($payload && isset($payload['id'])) $_SESSION['user_id'] = $payload['id'];
                    if ($payload && isset($payload['email'])) {
                        $_SESSION['user_email'] = $payload['email'];
                        if (isset($payload['name'])) $_SESSION['user_name'] = $payload['name'];
                    }
                    if ($payload && isset($payload['role'])) $_SESSION['user_role'] = $payload['role'];
                }
            } catch (Exception $e) {}
            
            $cookieExpire = time() + COOKIE_EXPIRE;
            setcookie(COOKIE_TOKEN, $googleToken, $cookieExpire, '/', '', false, true);
            
            header('Location: dashboard.php');
            exit;
        }

        // Sinkronisasi session dengan JWT
        if (isset($_SESSION['user_id'])) {
            $authTokenCheck = $_COOKIE[COOKIE_TOKEN] ?? null;
            $tokenValid = false;

            if ($authTokenCheck) {
                try {
                    $parts = explode('.', $authTokenCheck);
                    if (count($parts) === 3) {
                        $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
                        if ($payload && isset($payload['exp']) && $payload['exp'] > time()) {
                            $tokenValid = true;
                        }
                    }
                } catch (Exception $e) {}
            }

            if (!$tokenValid) {
                $_SESSION = [];
                if (ini_get('session.use_cookies')) {
                    $p = session_get_cookie_params();
                    setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
                }
                session_destroy();
                session_start();
            }
        }

        if (!isset($_SESSION['initiated'])) {
            session_regenerate_id(true);
            $_SESSION['initiated'] = true;
        }
    }
}

// 7. Auth Helpers
function setSecureCookie($name, $value, $expire = null) {
    if (headers_sent()) {
        error_log("[COOKIE] Headers already sent - cannot set cookie $name");
        return;
    }
    $expire = $expire ?? (time() + COOKIE_EXPIRE);
    $isProduction = (APP_ENV === 'production');
    setcookie($name, $value, [
        'expires' => $expire,
        'path' => '/',
        'domain' => '',
        'secure' => $isProduction,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    $_COOKIE[$name] = $value;
}

function deleteSecureCookie($name) {
    if (headers_sent()) {
        error_log("[COOKIE] Headers already sent - cannot delete cookie $name");
        return;
    }
    $isProduction = (APP_ENV === 'production');
    setcookie($name, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'domain' => '',
        'secure' => $isProduction,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
    unset($_COOKIE[$name]);
}

function getAuthToken() {
    return $_COOKIE[COOKIE_TOKEN] ?? null;
}

function setAuthToken($token, $user = null) {
    setSecureCookie(COOKIE_TOKEN, $token);
    if ($user) {
        if (!empty($user['username'])) setSecureCookie(COOKIE_USERNAME, $user['username']);
        if (!empty($user['plan'])) setSecureCookie(COOKIE_PLAN, $user['plan']);
        setSecureCookie(COOKIE_ADMIN, !empty($user['is_admin']) ? '1' : '0');
    }
}

function clearAuthToken() {
    deleteSecureCookie(COOKIE_TOKEN);
    deleteSecureCookie(COOKIE_USERNAME);
    deleteSecureCookie(COOKIE_PLAN);
    deleteSecureCookie(COOKIE_ADMIN);
}

// 8. JWT Decode (Firebase)
$vendorAutoload = __DIR__ . '/../vendor/autoload.php';
if (file_exists($vendorAutoload)) {
    require_once $vendorAutoload;
}

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;
use Firebase\JWT\BeforeValidException;

function decodeJWT($token) {
    if (!$token) return null;
    if (!class_exists('Firebase\JWT\JWT')) return null; // Guard jika vendor tidak ada
    
    $secret = getenv('JWT_SECRET');
    if (!$secret || strlen($secret) < 32) {
        error_log('[SECURITY] JWT_SECRET tidak valid atau tidak di-load');
        return null;
    }
    try {
        $payload = (array) JWT::decode($token, new Key($secret, 'HS256'));
        return $payload;
    } catch (ExpiredException $e) {
        return null;
    } catch (SignatureInvalidException $e) {
        error_log('[SECURITY] JWT signature INVALID - possible tampering! IP: ' . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
        return null;
    } catch (BeforeValidException $e) {
        return null;
    } catch (Exception $e) {
        error_log('[SECURITY] JWT decode error: ' . $e->getMessage());
        return null;
    }
}

function isTokenExpired($token) {
    $payload = decodeJWT($token);
    if (!$payload || !isset($payload['exp'])) return true;
    return $payload['exp'] < time();
}

// 9. User State - DENGAN PENGAMAN NULL
$authToken = getAuthToken();
$jwtPayload = decodeJWT($authToken);
$jwtPayload = is_array($jwtPayload) ? $jwtPayload : null; // GUARD

$isLoggedIn = $authToken && $jwtPayload && !isTokenExpired($authToken);
$userName = $_SESSION['user_name'] ?? ($jwtPayload['name'] ?? null) ?? ($jwtPayload['email'] ?? null);

if ($authToken && !$isLoggedIn) clearAuthToken();

if (!$userName && $isLoggedIn) {
    $userName = $_COOKIE[COOKIE_USERNAME] ?? ($jwtPayload['username'] ?? null);
}
$userPlan = $isLoggedIn ? ($_COOKIE[COOKIE_PLAN] ?? 'free') : 'free';
$isAdmin = $isLoggedIn && !empty($jwtPayload['is_admin']);
$userId = $isLoggedIn ? ($jwtPayload['userId'] ?? null) : null;

// 10. Helper Functions
function isPremium() {
    global $userPlan;
    return in_array($userPlan, ['pro', 'business', 'weekly', 'monthly']);
}

function formatDuration($seconds) {
    if ($seconds < 60) return round($seconds, 1) . 's';
    $mins = floor($seconds / 60);
    $secs = round($seconds % 60);
    return $mins . 'm ' . $secs . 's';
}

function getPlanBadgeClass($plan) {
    $map = ['free' => 'plan-free', 'pro' => 'plan-pro', 'business' => 'plan-business'];
    return $map[$plan] ?? 'plan-free';
}

function e($str) {
    return htmlspecialchars($str ?? '', ENT_QUOTES, 'UTF-8');
}

function redirect($url) {
    if (headers_sent()) {
        echo "<script>window.location.href='$url';</script>";
        exit;
    }
    header("Location: $url");
    exit;
}

// 11. Force Admin Pro
if (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['is_admin'])) {
    $_SESSION['user_plan'] = 'pro';
}

if ((is_array($jwtPayload) && !empty($jwtPayload['is_admin'])) || !empty($isAdmin)) {
    $userPlan = 'pro';
    $isAdmin = true;
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['is_admin'] = true;
        $_SESSION['user_plan'] = 'pro';
        if (is_array($jwtPayload)) {
            if (!empty($jwtPayload['userId'])) $_SESSION['user_id'] = $jwtPayload['userId'];
            if (!empty($jwtPayload['email'])) $_SESSION['user_email'] = $jwtPayload['email'];
            if (!empty($jwtPayload['username'])) $_SESSION['user_username'] = $jwtPayload['username'];
        }
    }
}

if (is_array($jwtPayload) && !empty($jwtPayload['userId']) && empty($_SESSION['user_id'])) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['user_id'] = $jwtPayload['userId'];
        if (!empty($jwtPayload['username'])) $_SESSION['user_username'] = $jwtPayload['username'];
        if (!empty($jwtPayload['email'])) $_SESSION['user_email'] = $jwtPayload['email'];
    }
}
