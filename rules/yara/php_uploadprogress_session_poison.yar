/*
  PHP session.upload_progress session-file poisoning
  Research tracking: CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")

  Detects a PHP session file whose content was injected via the
  session.upload_progress feature: the progress key "upload_progress_<attacker
  value>" and/or an uploaded filename carrying PHP open tags, serialized into a
  sess_* file. Code execution requires a separate app-side include() of this
  file; this rule flags the poisoned artifact, not an exploit.

  Status: PRE-ADVISORY, behavioral. Validate against your own lab capture.
  Author: php2shell-lab  (https://github.com/mikensec/php2shell-lab)
*/

rule PHP_UploadProgress_Session_Poison
{
    meta:
        description = "PHP session file poisoned via session.upload_progress content injection"
        reference   = "https://github.com/mikensec/php2shell-lab"
        cve         = "CVE-2026-109618, CVE-2026-109619"
        date        = "2026-10-21"
        confidence  = "high"
        status      = "pre-advisory"
    strings:
        $marker  = "upload_progress_" ascii
        $php     = "<?php" ascii nocase
        $short   = "<?=" ascii
        // progress key followed (within the serialized record) by a PHP open tag
        $chain   = /upload_progress_[^\x00|]{0,256}<\?/ ascii nocase
        // PHP session serializer framing, to bias toward real session files
        $ser     = /\b[a-zA-Z0-9_]{1,64}\|(a:\d+:\{|s:\d+:|i:\d+;|O:\d+:)/ ascii
    condition:
        $marker and ($chain or ($ser and ($php or $short)))
}

rule PHP_UploadProgress_Session_WriteDenial
{
    meta:
        description = "PHP session key containing '|' (serializer abort / silent write-denial primitive P5)"
        reference   = "https://github.com/mikensec/php2shell-lab"
        date        = "2026-10-21"
        confidence  = "medium"
        status      = "pre-advisory"
    strings:
        // a progress key that embeds a pipe triggers php_session_encode() failure
        $denial = /upload_progress_[^\x00]{0,128}\|/ ascii
    condition:
        $denial
}
