<?php
/* LAB ONLY — endpoint A: session.serialize_handler = php_serialize (via .htaccess).
 *
 * No app logic. session_start() alone is enough to make PHP write (or read) the
 * session file using this directory's handler. When session.upload_progress
 * fires during the multipart POST that reaches this path, the progress entry —
 * including whatever filename the uploader supplied — is written to the shared
 * session.save_path in php_serialize format.
 *
 * This file is not, and does not call, an include()/require() sink. It only
 * reproduces the configuration half of the handler-mismatch primitive.
 */
session_start();
header('Content-Type: text/plain');
echo "endpoint: app/upload.php\n";
echo "handler:  " . ini_get('session.serialize_handler') . "\n";
echo "sid:      " . session_id() . "\n";
