rule PHP_Dropper_FileWrite_Traversal {
    meta:
        description = "Detects file dropper using path traversal"
        severity = 9
    strings:
        $write      = /fopen\s*\(.*,\s*"w"\)/
        $traversal  = /fopen\s*\(.*\.\.\//
        $cmd        = /system\s*\(\s*"\$_GET\[/
        $fwrite     = "fwrite("
        $error_hide = "error_reporting(0)"
        $self_delete = "unlink("
    condition:
        ($write and $traversal) or $cmd or 3 of them
}

rule PHP_Dropper_Base64_Payload {
    meta:
        description = "Detects dropper writing base64-decoded payload"
        severity = 9
    strings:
        $drop    = "file_put_contents("
        $payload = "base64_decode("
        $remote  = "$_POST["
    condition:
        all of them
}

rule PHP_Dropper_SelfDelete {
    meta:
        description = "File that writes another file then deletes itself"
        severity = 8
    strings:
        $write  = "fwrite("
        $open   = /fopen\s*\(.*,\s*"w"\)/
        $delete = "unlink(__FILE__)"
    condition:
        all of them
}
