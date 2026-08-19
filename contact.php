<?php
/**
 * Contact form handler for software.spencerfields.com.
 *
 * Deliberately dependency-free: this is shared cPanel hosting, so PHP's own
 * mail() and a handful of cheap server-side checks beat pulling in a library
 * or a third-party form service that would see every customer message.
 *
 * Spam defences, cheapest first:
 *   1. Honeypot   -- a field people never see and bots reliably fill in.
 *   2. Timing     -- the form is stamped by script on load; a post with no
 *                    stamp never rendered the page, and one submitted within
 *                    a few seconds was not typed by a person.
 *   3. Validation -- required fields, real email, hard length caps.
 *   4. Injection  -- newlines are stripped from anything that reaches a mail
 *                    header. This is the one that actually matters: without
 *                    it the form becomes an open relay for spam.
 *   5. Link flood -- messages stuffed with URLs are the classic payload.
 *   6. Rate limit -- per-IP, to blunt anything that gets past the above.
 *
 * There is no CAPTCHA. The layers above stop commodity bots without making a
 * paying customer prove their humanity; if targeted spam ever gets through,
 * that is the point to add one.
 */

declare(strict_types=1);

/*
 * Apps@ is an alias on the spencer@spencerfields.com mailbox, defined in
 * Microsoft 365 -- which is where the domain's MX points.
 *
 * This only works because cPanel > Email Routing for spencerfields.com is set
 * to "Remote Mail Exchanger". It was previously "Local Mail Exchanger", which
 * made the web server believe it was the mail host: exim delivered on-box,
 * found no matching local mailbox, hit the domain's catch-all
 * (`*: :fail: No Such User Here`) and dropped every message -- after mail()
 * had already returned true, so the form reported success and nothing arrived.
 * If support mail ever goes quiet again, check that setting first.
 */
const MAIL_TO            = 'Apps@spencerfields.com';
const MAIL_FROM          = 'noreply@software.spencerfields.com';

// Cloudflare Worker relay (preferred delivery path -- see the send section).
// Deliberately the EasyPost worker: it is the same owner, relays to the same
// inbox, and is already proven. PHP mail() on this host has failed silently
// before, so the relay is the reliable path and worth reusing rather than
// standing up a second one. Messages identify themselves as Wren in the body.
const WORKER_CONTACT_URL = 'https://easypost-license-webhook.sgf36.workers.dev/contact';
// Kept above the document root so it is never web-servable, even if PHP
// execution is ever misconfigured.
const WORKER_SECRET_FILE = '/home2/spencgh6/.epd-contact-secret';

const MIN_FILL_SECONDS   = 3;
const MAX_FILL_AGE       = 86400;   // a stamp older than a day is stale
const MAX_LINKS          = 3;
const RATE_WINDOW        = 3600;    // per IP, per hour
const RATE_MAX           = 5;

/** Anything reaching a mail header must not be able to introduce one. */
function header_safe(string $value): string
{
    return trim(str_replace(["\r", "\n", "%0a", "%0d", "\0"], ' ', $value));
}

function client_ip(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown';
}

/**
 * Simple file-backed throttle. Best effort by design: on shared hosting the
 * temp directory is per-account, and a failure to read or write it must never
 * block a genuine message.
 */
function rate_limited(string $ip): bool
{
    $path = sys_get_temp_dir() . '/software-contact-' . hash('sha256', $ip) . '.txt';
    $now = time();
    $stamps = [];

    if (is_readable($path)) {
        $raw = @file_get_contents($path);
        if ($raw !== false) {
            foreach (explode(',', $raw) as $s) {
                $s = (int) $s;
                if ($s > $now - RATE_WINDOW) {
                    $stamps[] = $s;
                }
            }
        }
    }

    if (count($stamps) >= RATE_MAX) {
        return true;
    }

    $stamps[] = $now;
    @file_put_contents($path, implode(',', $stamps), LOCK_EX);
    return false;
}

function render(string $heading, string $body, bool $ok): void
{
    http_response_code($ok ? 200 : 400);
    $cls = $ok ? 'ok' : 'bad';
    $heading = htmlspecialchars($heading, ENT_QUOTES, 'UTF-8');
    $body = htmlspecialchars($body, ENT_QUOTES, 'UTF-8');
    echo <<<HTML
<!DOCTYPE html>
<html lang="en-GB">
<head><meta charset="utf-8">

<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{$heading} — Spencer Fields</title>
<!-- No webfont link. The privacy page states there are no third-party
     requests, and a Google Fonts stylesheet would quietly make that false. -->
<style>body{margin:0;background:#f7f5f1;color:#3d4a54;font-family:ui-sans-serif,-apple-system,"Segoe UI",system-ui,sans-serif;line-height:1.65}.wrap{max-width:44rem;margin:0 auto;padding:3rem 1.5rem}.topbar{display:flex;gap:1rem;align-items:center;border-bottom:1px solid #e0dad0;padding-bottom:1rem;margin-bottom:2rem}.brand{font-weight:700;color:#16212a;text-decoration:none}nav{margin-left:auto;display:flex;gap:1.1rem}nav a{color:#6c7a85;text-decoration:none;font-size:.93rem}h1{font-family:Georgia,serif;font-weight:400;color:#16212a}a{color:#1b5b53}.ok{color:#1b5b53}.bad{color:#a4433a}</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <a class="brand" href="index.html">Spencer Fields</a>
    <nav>
      <a href="index.html#software">Software</a>
      <a href="index.html#business">Business</a>
      <a href="index.html#contact">Contact</a>
    </nav>
  </div>
  <section>
    <h1>{$heading}</h1>
    <p class="{$cls}">{$body}</p>
    <p><a href="index.html#contact">Back to the site</a></p>
  </section>
</div>
</body>
</html>
HTML;
    exit;
}

// ---------------------------------------------------------------- handling

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Location: index.html#contact', true, 302);
    exit;
}

// 1. Honeypot.
if (trim((string) ($_POST['website'] ?? '')) !== '') {
    // Answer as though it worked. A bot told it failed simply retries.
    render('Thank you', 'Your message has been sent.', true);
}

// 2. Timing.
$ts = (int) ($_POST['ts'] ?? 0);           // milliseconds, set by script
$elapsed = $ts > 0 ? (time() - intdiv($ts, 1000)) : -1;
if ($elapsed < MIN_FILL_SECONDS || $elapsed > MAX_FILL_AGE) {
    render(
        'Message not sent',
        'This form could not be verified as a genuine submission. Please reload the page and try again, or write to us directly using the email address on the site.',
        false
    );
}

// 3. Validation.
$name    = header_safe((string) ($_POST['name'] ?? ''));
$email   = header_safe((string) ($_POST['email'] ?? ''));
$topic   = header_safe((string) ($_POST['topic'] ?? 'Something else'));
$message = trim((string) ($_POST['message'] ?? ''));

$errors = [];
if ($name === '' || mb_strlen($name) > 100) {
    $errors[] = 'a name';
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 150) {
    $errors[] = 'a valid email address';
}
if (mb_strlen($message) < 10 || mb_strlen($message) > 4000) {
    $errors[] = 'a message between 10 and 4000 characters';
}
if ($errors !== []) {
    render('Message not sent', 'Please provide ' . implode(', ', $errors) . '.', false);
}

// Must match the <select> on support.html exactly. When these drifted apart,
// every enquiry silently arrived as "Something else" and the categorisation
// was lost without anything reporting a problem.
$allowedTopics = [
    'A question about the software',
    'Licensing or business',
    'Press or partnership',
    'Something else',
];
if (!in_array($topic, $allowedTopics, true)) {
    $topic = 'Something else';
}

// 5. Link flood.
if (preg_match_all('~https?://~i', $message) > MAX_LINKS) {
    render(
        'Message not sent',
        'Your message contains too many links to be delivered. Please remove some and try again.',
        false
    );
}

// 6. Rate limit.
$ip = client_ip();
if (rate_limited($ip)) {
    render(
        'Message not sent',
        'Several messages have already been sent from this connection recently. Please try again later.',
        false
    );
}

// ------------------------------------------------------------------- send

$subject = header_safe('[Software] ' . $topic . ' — ' . $name);

$body = "A message was sent from the software.spencerfields.com contact form.\n\n"
      . "Name:    {$name}\n"
      . "Email:   {$email}\n"
      . "Topic:   {$topic}\n"
      . "IP:      {$ip}\n"
      . 'Time:    ' . gmdate('Y-m-d H:i:s') . " UTC\n\n"
      . "-----------------------------------------\n\n"
      . $message . "\n";

$headers = implode("\r\n", [
    'From: Wren <' . MAIL_FROM . '>',
    // Reply goes to the sender, while From stays on our own domain so the
    // message is not rejected as a forgery by the receiving server.
    'Reply-To: ' . header_safe($name) . ' <' . $email . '>',
    'Content-Type: text/plain; charset=UTF-8',
    'X-Mailer: software.spencerfields.com',
]);

/*
 * Delivery: Cloudflare Worker -> Resend first, PHP mail() as the fallback.
 *
 * mail() works, but Bluehost's shared outbound relays are poorly regarded by
 * Exchange Online: even with SPF, DKIM and DMARC all passing, Microsoft still
 * scored the message SCL:5 and filed it in Junk. That is reputation, not
 * authentication, so no DNS record fixes it -- it needs a sender with its own
 * standing, which is what Resend provides.
 *
 * The Resend key deliberately does not live on this shared host. The Worker
 * holds it; this side only knows a shared secret whose worst-case misuse is
 * sending Spencer mail at his own address.
 *
 * If the Worker is unreachable, misconfigured, or Resend rejects the send, we
 * fall back to mail(). A message landing in Junk is a far better failure than
 * a message silently lost.
 */
function relay_via_worker(array $payload, ?string &$error): bool
{
    $secretFile = WORKER_SECRET_FILE;
    if (!is_readable($secretFile)) {
        $error = 'shared secret file missing';
        return false;
    }
    $secret = trim((string) file_get_contents($secretFile));
    if ($secret === '') {
        $error = 'shared secret empty';
        return false;
    }

    $ch = curl_init(WORKER_CONTACT_URL);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'X-EPD-Contact-Secret: ' . $secret,
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 12,
        CURLOPT_CONNECTTIMEOUT => 6,
    ]);
    $response = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($status === 200) {
        return true;
    }
    $error = $curlErr !== '' ? $curlErr : "worker HTTP {$status}: " . substr((string) $response, 0, 200);
    return false;
}

$relayError = null;
/*
 * `product` tells the shared Worker which of the two products this is. Without
 * it every Wren enquiry was branded and auto-answered as Easy-Post Desktop:
 * the Worker had only these five fields to go on, and the two topic lists
 * overlap on "Bug report" and "Something else", so topic could not separate
 * them. The value must match a key in the Worker's PRODUCTS registry.
 */
$sent = relay_via_worker([
    'name' => $name,
    'email' => $email,
    'topic' => $topic,
    'product' => 'software',
    'message' => $message,
    'ip' => $ip,
], $relayError);

if (!$sent) {
    error_log('[software contact] Worker relay failed, falling back to mail(): ' . $relayError);
    $sent = @mail(MAIL_TO, $subject, $body, $headers, '-f' . MAIL_FROM);
}

if (!$sent) {
    render(
        'Message not sent',
        'Something went wrong sending your message. Please try again shortly, or use the email address shown on the site.',
        false
    );
}

render(
    'Thank you',
    'Your message has been sent. You will normally hear back within one business day.',
    true
);
