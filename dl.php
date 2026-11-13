<?php
/**
 * دانلود و ذخیره فایل روی سرور با cURL
 *
 * استفاده: save_file.php?url=لینک_فایل
 * فایل در همان پوشه اسکریپت ذخیره می‌شود.
 */
if(!isset($_GET["url"])){exit();}
// ---------------------- تنظیمات حداکثری ----------------------
set_time_limit(0);                    // بدون محدودیت زمان اجرا
ini_set('memory_limit', '512M');      // حافظه کافی برای هدرها و بافرهای کوچک
ignore_user_abort(true);              // حتی اگر کاربر صفحه را ببندد، دانلود ادامه یابد

// ---------------------- دریافت و اعتبارسنجی URL ----------------------
if (empty($_GET['url'])) {
    die('خطا: پارامتر url را وارد کنید. مثال: ?url=https://example.com/file.zip');
}

$url = trim($_GET['url']);

if (!filter_var($url, FILTER_VALIDATE_URL)) {
    die('خطا: آدرس وارد شده معتبر نیست.');
}

$scheme = parse_url($url, PHP_URL_SCHEME);
if (!in_array(strtolower($scheme), ['http', 'https'])) {
    die('خطا: فقط پروتکل HTTP و HTTPS پشتیبانی می‌شود.');
}

// ---------------------- تعیین نام فایل محلی ----------------------
$remotePath = parse_url($url, PHP_URL_PATH);
$filename = basename($remotePath);
if (empty($filename)) {
    $filename = 'downloaded_file_' . time(); // نام پیش‌فرض در صورت نبود نام
}

// مسیر ذخیره‌سازی: همان پوشه‌ای که اسکریپت در آن اجرا می‌شود
$savePath = __DIR__ . DIRECTORY_SEPARATOR . $filename;

// ---------------------- شروع دانلود و ذخیره‌سازی ----------------------
$fp = fopen($savePath, 'wb');
if ($fp === false) {
    die('خطا: نمی‌توان فایل را برای نوشتن باز کرد. دسترسی پوشه را بررسی کنید.');
}

$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => $url,
    CURLOPT_RETURNTRANSFER => false,         // مستقیماً در فایل بنویسد، نه در حافظه
    CURLOPT_FILE           => $fp,           // خروجی cURL به این handle فایل
    CURLOPT_FOLLOWLOCATION => true,          // دنبال کردن ریدایرکت‌ها
    CURLOPT_MAXREDIRS      => 20,
    CURLOPT_SSL_VERIFYPEER => false,         // در صورت نیاز به گواهی خودامضاء
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_USERAGENT      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    CURLOPT_TIMEOUT        => 0,             // دانلود هرگز تایم‌اوت نشود
    CURLOPT_CONNECTTIMEOUT => 30,
    CURLOPT_BUFFERSIZE     => 8192,          // بافر 8KB برای نوشتن در فایل
    // تنظیمات ضد قطعی: اگر سرعت زیر 1 بایت بر ثانیه افتاد، تا 10 دقیقه تحمل کن
    CURLOPT_LOW_SPEED_LIMIT => 1,
    CURLOPT_LOW_SPEED_TIME  => 600,
]);

curl_exec($ch);

// ---------------------- بررسی نتیجه ----------------------
$error = curl_error($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
fclose($fp);

if ($error) {
    // اگر خطایی بود، فایل ناقص را پاک کنیم
    @unlink($savePath);
    die("خطا در دانلود: $error");
}

if ($httpCode < 200 || $httpCode >= 400) {
    @unlink($savePath);
    die("خطا: سرور مبدأ کد وضعیت $httpCode را برگرداند.");
}

echo "فایل با موفقیت دانلود و ذخیره شد:\n";
echo "نام فایل: $filename\n";
echo "مسیر کامل: $savePath\n";
echo "حجم فایل: " . round(filesize($savePath) / 1048576, 2) . " مگابایت\n";
?>