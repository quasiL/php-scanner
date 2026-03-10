rule PHP_Webshell_Interactive_GET {
    meta:
        description = "Interactive webshell accepting commands via GET"
        severity = 10
    strings:
        $get_cmd = /\$_GET\s*\[\s*['"]cmd['"]\s*\]/
        $exec1   = "shell_exec("
        $exec2   = "passthru("
        $exec3   = "proc_open("
        $exec4   = "system("
        $exec5   = "popen("
    condition:
        $get_cmd and any of ($exec*)
}

rule PHP_Webshell_Interactive_POST {
    meta:
        description = "Interactive webshell accepting commands via POST"
        severity = 10
    strings:
        $post_cmd = /\$_POST\s*\[\s*['"]cmd['"]\s*\]/
        $exec1    = "shell_exec("
        $exec2    = "passthru("
        $exec3    = "proc_open("
        $exec4    = "system("
        $exec5    = "popen("
    condition:
        $post_cmd and any of ($exec*)
}

rule PHP_Webshell_PasswordProtected {
    meta:
        description = "Password-protected webshell like c99, r57, WSO"
        severity = 9
    strings:
        $pass     = /md5\s*\(\s*\$_(GET|POST|REQUEST)/
        $auth     = /if\s*\(\s*\$_POST\s*\[\s*['"]pass['"]\s*\]/
        $filelist = "scandir("
        $dirlist  = "glob("
    condition:
        ($pass or $auth) and ($filelist or $dirlist)
}

rule PHP_Webshell_FileManager {
    meta:
        description = "Webshell with file manager capabilities"
        severity = 8
    strings:
        $upload  = "$_FILES["
        $move    = "move_uploaded_file("
        $exec    = "system("
        $read    = "file_get_contents("
        $write   = "file_put_contents("
    condition:
        $upload and $move and ($exec or $write or $read)
}
