<?php
/* dl2.php | PHP 7.4+ | Requires cURL
   Use: https://your-domain.com/dl2.php?url=https%3A%2F%2Fexample.com%2Ffile.zip
*/
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('log_errors', '1');
ini_set('display_errors', '0');

const STEP_TIME = 7;
const CONNECT_TIME = 5;
const MAX_REDIRECTS = 12;
const MAX_RETRIES = 10;
const JOB_TTL = 86400;
const DOWNLOAD_DIR = __DIR__ . '/downloads';
const JOB_DIR_NAME = 'dl2_jobs_v4';
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126 Safari/537.36';

function out(array $data, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function jobDir(): string {
    $dir = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . JOB_DIR_NAME . '_' . substr(hash('sha256', __DIR__), 0, 16);
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException('ساخت پوشه موقت ممکن نیست.');
    }
    @chmod($dir, 0700);
    return $dir;
}

function checkId(string $id): string {
    if (!preg_match('/^[a-f0-9]{32}$/', $id)) throw new RuntimeException('شناسه دانلود نامعتبر است.');
    return $id;
}

function jobPath(string $id): string {
    return jobDir() . '/' . checkId($id) . '.json';
}

function partPath(string $id): string {
    return DOWNLOAD_DIR . '/.parts/' . checkId($id) . '.part';
}

function saveJob(string $id, array $job): void {
    $path = jobPath($id);
    $tmp = $path . '.tmp';
    $json = json_encode($job, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false || @file_put_contents($tmp, $json, LOCK_EX) === false) throw new RuntimeException('ذخیره وضعیت دانلود ناموفق بود.');
    @chmod($tmp, 0600);
    if (!@rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('به‌روزرسانی وضعیت دانلود ناموفق بود.');
    }
    @chmod($path, 0600);
}

function loadJob(string $id): array {
    $path = jobPath($id);
    if (!is_file($path)) throw new RuntimeException('دانلود پیدا نشد؛ لینک را دوباره باز کنید.');
    $job = json_decode((string)@file_get_contents($path), true);
    if (!is_array($job)) throw new RuntimeException('اطلاعات دانلود خراب است.');
    if (time() - (int)($job['created'] ?? 0) > JOB_TTL) throw new RuntimeException('اطلاعات دانلود منقضی شده است؛ لینک را دوباره باز کنید.');
    return $job;
}

function makeDirs(): void {
    if (!is_dir(DOWNLOAD_DIR) && !@mkdir(DOWNLOAD_DIR, 0755, true) && !is_dir(DOWNLOAD_DIR)) throw new RuntimeException('ساخت پوشه downloads ناموفق بود.');
    if (!is_writable(DOWNLOAD_DIR)) throw new RuntimeException('پوشه downloads قابل نوشتن نیست؛ مجوز پوشه را بررسی کنید.');

    $parts = DOWNLOAD_DIR . '/.parts';
    if (!is_dir($parts) && !@mkdir($parts, 0700, true) && !is_dir($parts)) throw new RuntimeException('ساخت پوشه موقت ناموفق بود.');
    @chmod($parts, 0700);

    if (!is_file(DOWNLOAD_DIR . '/.htaccess')) {
        @file_put_contents(DOWNLOAD_DIR . '/.htaccess', "Options -Indexes\n<FilesMatch \"\\.(php[0-9]*|phtml|phar|cgi|pl|py|rb|sh|shtml)$\">\nRequire all denied\n</FilesMatch>\n");
    }
    if (!is_file(DOWNLOAD_DIR . '/index.html')) @file_put_contents(DOWNLOAD_DIR . '/index.html', '');
    @file_put_contents($parts . '/.htaccess', "Require all denied\n");
    @file_put_contents($parts . '/index.html', '');
}

/* Resolve the hostname and pin cURL to a public IPv4 to avoid internal-network requests. */
function urlInfo(string $url): array {
    $url = trim($url);
    if ($url === '' || strlen($url) > 6000 || preg_match('/[\x00-\x20\x7f]/', $url) || !filter_var($url, FILTER_VALIDATE_URL)) throw new RuntimeException('لینک URL معتبر نیست.');

    $p = parse_url($url);
    if (!$p || empty($p['scheme']) || empty($p['host'])) throw new RuntimeException('ساختار لینک معتبر نیست.');

    $scheme = strtolower((string)$p['scheme']);
    if (!in_array($scheme, ['http', 'https'], true)) throw new RuntimeException('فقط HTTP و HTTPS مجاز است.');
    if (isset($p['user']) || isset($p['pass'])) throw new RuntimeException('لینک دارای نام کاربری یا رمز داخل URL پشتیبانی نمی‌شود.');

    $host = strtolower(rtrim((string)$p['host'], '.'));
    $port = (int)($p['port'] ?? ($scheme === 'https' ? 443 : 80));
    if (!in_array($port, [80, 443], true)) throw new RuntimeException('فقط پورت‌های 80 و 443 مجاز هستند.');
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) throw new RuntimeException('IPv6 در این نسخه پشتیبانی نمی‌شود.');

    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ips = [$host];
    } else {
        if (!preg_match('/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/D', $host)) throw new RuntimeException('نام دامنه معتبر نیست.');

        $ips = [];
        if (function_exists('dns_get_record')) {
            $records = @dns_get_record($host, DNS_A);
            if (is_array($records)) foreach ($records as $r) if (!empty($r['ip'])) $ips[] = (string)$r['ip'];
        }
        if (!$ips) {
            $fallback = @gethostbynamel($host);
            if (is_array($fallback)) $ips = $fallback;
        }
    }

    $ips = array_values(array_unique($ips));
    if (!$ips) throw new RuntimeException('DNS دامنه مقصد قابل resolve نیست.');

    foreach ($ips as $ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) throw new RuntimeException('آدرس خصوصی یا داخلی قابل دانلود نیست.');
    }

    return ['host' => $host, 'port' => $port, 'ip' => $ips[0]];
}

function redirectUrl(string $base, string $location): string {
    $location = trim($location);
    if ($location === '') throw new RuntimeException('هدر Location در ریدایرکت خالی است.');
    if (preg_match('#^https?://#i', $location)) return $location;

    $b = parse_url($base);
    if (!$b || empty($b['scheme']) || empty($b['host'])) throw new RuntimeException('آدرس ریدایرکت نامعتبر است.');

    $origin = $b['scheme'] . '://' . $b['host'] . (isset($b['port']) ? ':' . $b['port'] : '');
    if (strncmp($location, '//', 2) === 0) return $b['scheme'] . ':' . $location;

    $fragment = '';
    $h = strpos($location, '#');
    if ($h !== false) {
        $fragment = substr($location, $h);
        $location = substr($location, 0, $h);
    }

    if ($location === '') return $base . $fragment;
    if ($location[0] === '?') return $origin . ($b['path'] ?? '/') . $location . $fragment;

    if ($location[0] === '/') $path = $location;
    else {
        $old = $b['path'] ?? '/';
        $pos = strrpos($old, '/');
        $path = ($pos === false ? '/' : substr($old, 0, $pos + 1)) . $location;
    }

    $query = '';
    $q = strpos($path, '?');
    if ($q !== false) {
        $query = substr($path, $q);
        $path = substr($path, 0, $q);
    }

    $segments = [];
    foreach (explode('/', $path) as $segment) {
        if ($segment === '' || $segment === '.') continue;
        if ($segment === '..') array_pop($segments);
        else $segments[] = $segment;
    }

    return $origin . '/' . implode('/', $segments) . $query . $fragment;
}

function safeName(string $name): string {
    $name = basename(str_replace('\\', '/', $name));
    $name = preg_replace('/[\x00-\x1F\x7F\\\\\/:*?"<>|]+/u', '_', $name) ?? '';
    $name = trim($name, ". \t\n\r\0\x0B");
    if ($name === '' || $name === '.' || $name === '..') $name = 'download_' . date('Ymd_His') . '.bin';
    if (preg_match('/\.(php[0-9]*|phtml|phar|cgi|pl|py|rb|sh|shtml|user\.ini)$/i', $name)) $name .= '.download';
    return substr($name, 0, 180);
}

function responseName(array $headers, string $url): string {
    $cd = (string)($headers['content-disposition'] ?? '');
    $name = '';

    if (preg_match("/filename\\*\\s*=\\s*UTF-8''([^;]+)/i", $cd, $m)) $name = rawurldecode(trim($m[1], " \t\\\"'"));
    elseif (preg_match('/filename\s*=\s*"([^"]+)"/i', $cd, $m)) $name = $m[1];
    elseif (preg_match('/filename\s*=\s*([^;]+)/i', $cd, $m)) $name = trim($m[1], " \t\\\"'");

    if ($name === '') $name = rawurldecode(basename((string)(parse_url($url, PHP_URL_PATH) ?? '')));
    return safeName($name);
}

function publicUrl(string $filename): string {
    $script = str_replace('\\', '/', (string)($_SERVER['SCRIPT_NAME'] ?? '/dl2.php'));
    $base = rtrim(dirname($script), '/.');
    return ($base !== '' ? $base : '') . '/downloads/' . rawurlencode($filename);
}

function finishJob(string $id, array &$job, string $part): array {
    if (!is_file($part)) throw new RuntimeException('فایل موقت پیدا نشد.');

    $name = safeName((string)($job['filename'] ?? ''));
    $target = DOWNLOAD_DIR . '/' . $name;

    if (file_exists($target)) {
        $ext = pathinfo($name, PATHINFO_EXTENSION);
        $stem = pathinfo($name, PATHINFO_FILENAME);
        $name = $stem . '_' . substr($id, 0, 8) . ($ext !== '' ? '.' . $ext : '');
        $target = DOWNLOAD_DIR . '/' . $name;
    }

    if (!@rename($part, $target)) throw new RuntimeException('انتقال فایل نهایی به پوشه downloads ناموفق بود.');

    $job['filename'] = $name;
    $job['bytes'] = (int)@filesize($target);
    $job['status'] = 'complete';
    $job['updated'] = time();
    saveJob($id, $job);

    return ['ok' => true, 'status' => 'complete', 'filename' => $name, 'url' => publicUrl($name), 'bytes' => $job['bytes']];
}

function failJob(string $id, array &$job, string $message): void {
    $job['status'] = 'error';
    $job['error'] = $message;
    $job['updated'] = time();
    @unlink(partPath($id));
    saveJob($id, $job);
}

/* API requests */
$action = (string)($_POST['action'] ?? '');

if ($action !== '') {
    if (!extension_loaded('curl')) out(['ok' => false, 'error' => 'افزونه PHP cURL روی هاست فعال نیست.'], 503);

    ignore_user_abort(true);
    @set_time_limit(STEP_TIME + 5);

    try {
        if ($action === 'start') {
            $url = trim((string)($_POST['url'] ?? ''));
            urlInfo($url);
            makeDirs();

            $id = bin2hex(random_bytes(16));

            saveJob($id, [
                'url' => $url,
                'status' => 'active',
                'created' => time(),
                'updated' => time(),
                'filename' => '',
                'expected' => null,
                'bytes' => 0,
                'stalls' => 0,
                'redirects' => 0,
                'error' => ''
            ]);

            out(['ok' => true, 'id' => $id]);
        }

        if ($action !== 'step') out(['ok' => false, 'error' => 'عملیات نامعتبر است.'], 400);

        $id = (string)($_POST['id'] ?? '');
        $job = loadJob($id);

        if (($job['status'] ?? '') === 'complete') {
            out(['ok' => true, 'status' => 'complete', 'filename' => $job['filename'], 'url' => publicUrl($job['filename']), 'bytes' => (int)$job['bytes']]);
        }

        if (($job['status'] ?? '') === 'error') out(['ok' => false, 'error' => $job['error'] ?? 'دانلود متوقف شده است.']);

        $lock = @fopen(jobDir() . '/' . $id . '.lock', 'c');

        if (!$lock || !@flock($lock, LOCK_EX | LOCK_NB)) {
            if (is_resource($lock)) fclose($lock);
            out(['ok' => true, 'status' => 'active', 'busy' => true]);
        }

        try {
            $part = partPath($id);
            $offset = is_file($part) ? (int)filesize($part) : 0;
            $deadline = microtime(true) + STEP_TIME;
            $url = (string)$job['url'];
            $redirectCount = 0;

            $curlResult = false;
            $curlErrno = 0;
            $curlError = '';
            $http = 0;
            $headers = [];
            $rangeIgnored = false;
            $badRange = false;
            $writeFailed = false;

            while (microtime(true) < $deadline) {
                $resolved = urlInfo($url);
                $remaining = max(1, (int)floor($deadline - microtime(true)));

                $fp = @fopen($part, $offset > 0 ? 'ab' : 'wb');
                if (!$fp) throw new RuntimeException('فایل موقت قابل نوشتن نیست؛ فضای دیسک و مجوز پوشه را بررسی کنید.');

                $headers = [];
                $rangeIgnored = false;
                $badRange = false;
                $writeFailed = false;
                $responseStatus = 0;

                $ch = curl_init();

                $options = [
                    CURLOPT_URL => $url,
                    CURLOPT_RETURNTRANSFER => false,
                    CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_CONNECTTIMEOUT => min(CONNECT_TIME, $remaining),
                    CURLOPT_TIMEOUT => min(STEP_TIME, $remaining),
                    CURLOPT_NOSIGNAL => true,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_USERAGENT => USER_AGENT,
                    CURLOPT_HTTPHEADER => ['Accept-Encoding: identity'],
                    CURLOPT_BUFFERSIZE => 65536,

                    CURLOPT_HEADERFUNCTION => function ($curl, string $line) use (&$headers, &$responseStatus, &$rangeIgnored, &$badRange, $offset): int {
                        $len = strlen($line);
                        $trim = trim($line);

                        if (preg_match('/^HTTP\/\S+\s+(\d{3})/i', $trim, $m)) {
                            $responseStatus = (int)$m[1];
                            $headers = [];
                            return $len;
                        }

                        if ($trim === '') {
                            if ($offset > 0 && $responseStatus === 200) $rangeIgnored = true;

                            if ($responseStatus === 206) {
                                $cr = (string)($headers['content-range'] ?? '');
                                if (!preg_match('/^bytes\s+(\d+)-\d+\/(\d+|\*)$/i', $cr, $m) || (int)$m[1] !== $offset) $badRange = true;
                            }
                            return $len;
                        }

                        $colon = strpos($line, ':');
                        if ($colon !== false) $headers[strtolower(trim(substr($line, 0, $colon)))] = trim(substr($line, $colon + 1));
                        return $len;
                    },

                    CURLOPT_WRITEFUNCTION => function ($curl, string $data) use (&$responseStatus, &$rangeIgnored, &$badRange, &$writeFailed, $fp): int {
                        $len = strlen($data);

                        if ($responseStatus < 200 || $responseStatus >= 300 || $rangeIgnored || $badRange) return $len;

                        $done = 0;
                        while ($done < $len) {
                            $n = @fwrite($fp, substr($data, $done));
                            if ($n === false || $n === 0) {
                                $writeFailed = true;
                                return 0;
                            }
                            $done += $n;
                        }
                        return $done;
                    }
                ];

                $options[CURLOPT_RANGE] = $offset . '-';

                if (!filter_var($resolved['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                    $options[CURLOPT_RESOLVE] = [$resolved['host'] . ':' . $resolved['port'] . ':' . $resolved['ip']];
                }

                if (defined('CURLOPT_PROTOCOLS')) $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS;

                curl_setopt_array($ch, $options);

                $curlResult = curl_exec($ch);
                $curlErrno = curl_errno($ch);
                $curlError = curl_error($ch);
                $info = curl_getinfo($ch);
                $http = (int)($info['http_code'] ?? $responseStatus);

                curl_close($ch);

                @fflush($fp);
                if (function_exists('fsync')) @fsync($fp);
                fclose($fp);

                if ($rangeIgnored) {
                    failJob($id, $job, 'سرور مقصد HTTP Range را نادیده می‌گیرد؛ ادامه دانلود امن نیست و متوقف شد.');
                    out(['ok' => false, 'error' => $job['error']]);
                }

                if ($badRange) {
                    failJob($id, $job, 'پاسخ Range سرور مقصد معتبر نیست.');
                    out(['ok' => false, 'error' => $job['error']]);
                }

                if (in_array($http, [301, 302, 303, 307, 308], true)) {
                    $location = (string)($headers['location'] ?? '');
                    $job['redirects'] = (int)$job['redirects'] + 1;
                    $redirectCount++;

                    if ($location === '' || (int)$job['redirects'] > MAX_REDIRECTS) throw new RuntimeException('ریدایرکت ناقص است یا تعداد انتقال‌ها بیش از حد شده است.');

                    $url = redirectUrl($url, $location);
                    urlInfo($url);
                    $job['url'] = $url;

                    if ($redirectCount >= MAX_REDIRECTS) break;
                    continue;
                }

                break;
            }

            if (in_array($http, [301, 302, 303, 307, 308], true)) {
                $job['url'] = $url;
                $job['updated'] = time();
                saveJob($id, $job);

                clearstatcache(true, $part);
                out([
                    'ok' => true,
                    'status' => 'active',
                    'bytes' => is_file($part) ? (int)filesize($part) : 0,
                    'expected' => $job['expected'],
                    'message' => 'در حال دنبال‌کردن لینک انتقالی…'
                ]);
            }

            clearstatcache(true, $part);
            $bytes = is_file($part) ? (int)filesize($part) : 0;

            if ($writeFailed || $curlErrno === 23) {
                failJob($id, $job, 'نوشتن روی دیسک ناموفق بود؛ فضای خالی و مجوز پوشه را بررسی کنید.');
                out(['ok' => false, 'error' => $job['error']]);
            }

            if ($http === 416) {
                $cr = (string)($headers['content-range'] ?? '');

                if (preg_match('/^bytes\s+\*\/(\d+)$/i', $cr, $m) && (int)$m[1] === $bytes) {
                    if (empty($job['filename'])) $job['filename'] = responseName($headers, $url);
                    out(finishJob($id, $job, $part));
                }

                failJob($id, $job, 'سرور کد 416 داد اما اندازه فایل با داده دریافتی مطابقت ندارد.');
                out(['ok' => false, 'error' => $job['error']]);
            }

            if (in_array($http, [408, 425, 429, 500, 502, 503, 504], true)) {
                $job['stalls'] = (int)$job['stalls'] + 1;
                $job['bytes'] = $bytes;

                if ((int)$job['stalls'] >= MAX_RETRIES) {
                    failJob($id, $job, 'سرور مقصد پس از چند تلاش پاسخ مناسب نمی‌دهد.');
                    out(['ok' => false, 'error' => $job['error']]);
                }

                saveJob($id, $job);
                out(['ok' => true, 'status' => 'active', 'bytes' => $bytes, 'expected' => $job['expected'], 'message' => 'خطای موقت سرور؛ تلاش مجدد…']);
            }

            if ($http === 0 && in_array($curlErrno, [7, 18, 28, 52, 55, 56], true)) {
                $job['stalls'] = (int)$job['stalls'] + 1;
                $job['bytes'] = $bytes;

                if ((int)$job['stalls'] >= MAX_RETRIES) {
                    failJob($id, $job, 'ارتباط با سرور مقصد برقرار نشد: ' . $curlError);
                    out(['ok' => false, 'error' => $job['error']]);
                }

                saveJob($id, $job);
                out(['ok' => true, 'status' => 'active', 'bytes' => $bytes, 'expected' => $job['expected'], 'message' => 'اتصال موقتاً قطع شد؛ تلاش مجدد…']);
            }

            if ($http >= 400) {
                failJob($id, $job, 'سرور مقصد خطای HTTP ' . $http . ' برگرداند؛ ممکن است لینک منقضی یا دسترسی آن محدود باشد.');
                out(['ok' => false, 'error' => $job['error']]);
            }

            if (!in_array($http, [200, 206], true)) {
                failJob($id, $job, 'پاسخ نامعتبر سرور مقصد: HTTP ' . $http . ($curlError ? ' / ' . $curlError : ''));
                out(['ok' => false, 'error' => $job['error']]);
            }

            if ($http === 206) {
                $cr = (string)($headers['content-range'] ?? '');

                if (!preg_match('/^bytes\s+(\d+)-\d+\/(\d+|\*)$/i', $cr, $m) || (int)$m[1] !== $offset) {
                    failJob($id, $job, 'هدر Content-Range سرور مقصد معتبر نیست.');
                    out(['ok' => false, 'error' => $job['error']]);
                }

                $job['expected'] = ($m[2] === '*') ? null : (int)$m[2];

            } elseif (isset($headers['content-length']) && ctype_digit((string)$headers['content-length'])) {
                $job['expected'] = (int)$headers['content-length'];
            }

            if (empty($job['filename'])) $job['filename'] = responseName($headers, $url);

            if ($curlErrno !== 0 && !in_array($curlErrno, [18, 28, 52, 55, 56], true)) {
                failJob($id, $job, 'خطای cURL: ' . ($curlError ?: 'اتصال ناموفق'));
                out(['ok' => false, 'error' => $job['error']]);
            }

            $expected = $job['expected'] === null ? null : (int)$job['expected'];

            if ($expected !== null && $bytes > $expected) {
                failJob($id, $job, 'حجم دریافتی از اندازه اعلام‌شده سرور بیشتر شد.');
                out(['ok' => false, 'error' => $job['error']]);
            }

            if ($bytes > (int)($job['bytes'] ?? 0)) $job['stalls'] = 0;
            elseif ($curlErrno !== 0) $job['stalls'] = (int)$job['stalls'] + 1;

            if ((int)$job['stalls'] >= MAX_RETRIES) {
                failJob($id, $job, 'چند بار ارتباط بدون دریافت داده قطع شد.');
                out(['ok' => false, 'error' => $job['error']]);
            }

            $job['bytes'] = $bytes;
            $job['updated'] = time();

            if ($expected !== null && $bytes === $expected) out(finishJob($id, $job, $part));
            if ($curlResult === true && $expected === null) out(finishJob($id, $job, $part));

            saveJob($id, $job);
            out(['ok' => true, 'status' => 'active', 'bytes' => $bytes, 'expected' => $job['expected'], 'message' => 'دانلود ادامه دارد…']);

        } finally {
            @flock($lock, LOCK_UN);
            fclose($lock);
        }

    } catch (Throwable $e) {
        error_log('dl2.php: ' . $e->getMessage());
        out(['ok' => false, 'error' => $e->getMessage()], 400);
    }
}

/* Web page */
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
$initialUrl = isset($_GET['url']) ? trim((string)$_GET['url']) : '';
?>
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>دانلود مستقیم روی سرور</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;background:#0b1220;color:#e5e7eb;font-family:Tahoma,Arial,sans-serif}.card{width:min(720px,100%);padding:28px;background:#111c2e;border:1px solid #2a3a52;border-radius:18px;box-shadow:0 20px 65px #0007}h1{font-size:22px;margin:0 0 10px}.desc,.hint{color:#a9b8cc;font-size:13px;line-height:2}.desc{margin:0 0 22px}label{display:block;margin:15px 0 8px;font-size:13px}input{width:100%;padding:14px;border-radius:10px;border:1px solid #394b65;background:#0a1424;color:#fff;font-size:13px}button{width:100%;padding:14px;margin-top:16px;border:0;border-radius:10px;background:#0284c7;color:white;font-weight:bold;font-size:15px;cursor:pointer}button:disabled{opacity:.55;cursor:wait}.progress{height:12px;border-radius:30px;background:#26364c;overflow:hidden;margin-top:24px;display:none}.bar{width:0;height:100%;background:linear-gradient(90deg,#06b6d4,#22c55e)}.status{font-size:13px;line-height:2;margin-top:14px;overflow-wrap:anywhere}.result{display:none;margin-top:16px;padding:13px;border-radius:10px;background:#12372f}.result a{color:#86efac;font-weight:bold;text-decoration:none}.hint{margin-top:22px;padding-top:15px;border-top:1px solid #2a3a52;font-size:12px}.badge{display:inline-block;margin-bottom:14px;padding:5px 10px;border-radius:30px;background:#12344b;color:#7dd3fc;font-size:11px}
</style>
</head>
<body>
<div class="card">
    <span class="badge">cPanel · DirectAdmin · Shared Hosting</span>
    <h1>دانلود مستقیم روی سرور</h1>
    <p class="desc">لینک را وارد کن یا همین صفحه را با پارامتر <b dir="ltr">?url=</b> باز کن. دانلود خودکار شروع می‌شود و فایل داخل پوشه downloads ذخیره خواهد شد.</p>

    <form id="form">
        <label for="url">لینک فایل</label>
        <input id="url" type="url" dir="ltr" placeholder="https://example.com/file.zip" required>
        <button id="button" type="submit">شروع دانلود</button>
    </form>

    <div class="progress" id="progress"><div class="bar" id="bar"></div></div>
    <div class="status" id="status"></div>
    <div class="result" id="result"></div>
    <div class="hint">درخواست‌ها کوتاه هستند تا احتمال Timeout کمتر شود. ادامه دانلود از محل قطع‌شده به پشتیبانی HTTP Range در سرور مقصد نیاز دارد. صفحه را تا پایان دانلود باز نگه دار.</div>
</div>

<script>
(() => {
    'use strict';

    const initialUrl = <?= json_encode($initialUrl, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    const $ = id => document.getElementById(id);
    const form = $('form'), button = $('button'), statusBox = $('status');
    let running = false;
    const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

    function fmt(value) {
        let n = Number(value || 0), units = ['B','KB','MB','GB','TB'], i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return n.toFixed(i ? 2 : 0) + ' ' + units[i];
    }

    async function api(data) {
        const response = await fetch(location.pathname, {
            method: 'POST',
            headers: {'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},
            body: new URLSearchParams(data).toString(),
            cache: 'no-store',
            credentials: 'same-origin'
        });

        let result;
        try { result = await response.json(); }
        catch (e) { throw new Error('پاسخ PHP معتبر نیست؛ لاگ خطای هاست را بررسی کنید.'); }

        if (!response.ok || !result.ok) throw new Error(result.error || 'خطای سرور');
        return result;
    }

    function showProgress(bytes, total) {
        $('progress').style.display = 'block';

        if (total !== null && total !== undefined && Number(total) > 0) {
            const p = Math.min(100, Number(bytes) / Number(total) * 100);
            $('bar').style.width = p.toFixed(2) + '%';
            statusBox.textContent = 'دریافت‌شده: ' + fmt(bytes) + ' از ' + fmt(total) + ' (' + p.toFixed(1) + '٪)';
        } else {
            $('bar').style.width = '100%';
            statusBox.textContent = 'دریافت‌شده: ' + fmt(bytes) + ' (حجم کل اعلام نشده است)';
        }
    }

    async function runJob(id) {
        if (running) return;

        running = true;
        button.disabled = true;
        $('result').style.display = 'none';
        statusBox.textContent = 'در حال دریافت فایل از سرور مقصد…';

        try {
            while (true) {
                const d = await api({action:'step', id:id});

                if (d.busy) {
                    await sleep(900);
                    continue;
                }

                if (d.status === 'complete') {
                    $('progress').style.display = 'block';
                    $('bar').style.width = '100%';
                    statusBox.textContent = 'دانلود کامل شد: ' + fmt(d.bytes);

                    const a = document.createElement('a');
                    a.href = d.url;
                    a.target = '_blank';
                    a.rel = 'noopener';
                    a.textContent = 'باز کردن فایل ذخیره‌شده: ' + d.filename;

                    $('result').replaceChildren(a);
                    $('result').style.display = 'block';
                    localStorage.removeItem('dl2_active_job');
                    break;
                }

                showProgress(d.bytes, d.expected);
                if (d.message) statusBox.textContent += ' — ' + d.message;
                await sleep(350);
            }

        } catch (e) {
            statusBox.textContent = 'خطا: ' + e.message;

        } finally {
            running = false;
            button.disabled = false;
        }
    }

    async function startDownload(url) {
        if (running) return;

        button.disabled = true;
        statusBox.textContent = 'در حال آماده‌سازی دانلود…';
        $('progress').style.display = 'block';
        $('bar').style.width = '0%';
        $('result').style.display = 'none';

        try {
            const d = await api({action:'start', url:url});
            localStorage.setItem('dl2_active_job', JSON.stringify({id:d.id, url:url}));
            await runJob(d.id);

        } catch (e) {
            statusBox.textContent = 'خطا: ' + e.message;
            button.disabled = false;
        }
    }

    form.addEventListener('submit', e => {
        e.preventDefault();
        const u = $('url').value.trim();
        if (u) startDownload(u);
    });

    let saved = null;

    try {
        saved = JSON.parse(localStorage.getItem('dl2_active_job') || 'null');
    } catch (e) {
        localStorage.removeItem('dl2_active_job');
    }

    if (initialUrl) {
        $('url').value = initialUrl;

        if (saved && saved.id && saved.url === initialUrl) runJob(saved.id);
        else startDownload(initialUrl);

    } else if (saved && saved.id && saved.url) {
        $('url').value = saved.url;
        runJob(saved.id);
    }
})();
</script>
</body>
</html>
