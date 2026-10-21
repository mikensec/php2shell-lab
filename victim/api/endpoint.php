<?php
/* LAB ONLY — endpoint B: session.serialize_handler = php (via .htaccess).
 *
 * No app logic. session_start() alone is enough to make PHP READ the shared
 * session file with this directory's handler. If app/upload.php already wrote
 * it in php_serialize format (see that file), this read is the format
 * mismatch: PHP's 'php' decoder treats the raw '|' the uploaded filename may
 * contain as a field delimiter rather than as data trapped inside a
 * php_serialize length-prefixed string, which is the undefined-behaviour edge
 * this CVE's handler-mismatch primitive relies on.
 *
 * Any decode warning PHP emits lands in /captures/php_error.log (log_errors is
 * on, display_errors is off — nothing is reflected to the client). $_SESSION
 * is dumped below only for your own observation inside this sealed lab.
 *
 * This file is not, and does not call, an include()/require() sink. Whatever
 * lands in $_SESSION is inert data here; this repo deliberately stops short
 * of providing a gadget class to turn decode into execution.
 */
session_start();
header('Content-Type: text/plain');
echo "endpoint: api/endpoint.php\n";
echo "handler:  " . ini_get('session.serialize_handler') . "\n";
echo "sid:      " . session_id() . "\n";
echo "session:  " . var_export($_SESSION, true) . "\n";
