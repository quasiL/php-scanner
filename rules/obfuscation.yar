rule PHP_Obfuscation_Eval_Encoded {
    meta:
        description = "eval wrapping encoded payload"
        severity = 8
    strings:
        $s1 = /eval\s*\(\s*base64_decode/
        $s2 = /eval\s*\(\s*gzinflate/
        $s3 = /eval\s*\(\s*str_rot13/
        $s4 = /eval\s*\(\s*gzuncompress/
        $s5 = /eval\s*\(\s*gzdecode/
        $s6 = /eval\s*\(\s*urldecode/
    condition:
        any of them
}

rule PHP_Obfuscation_Chr_Concat {
    meta:
        description = "Function name built with chr() concatenation"
        severity = 7
    strings:
        $chr = /\$[^=]+= *(chr\([0-9]+\)\.?){2,}/
    condition:
        $chr
}

rule PHP_Obfuscation_Hex_Strings {
    meta:
        description = "Hex-encoded string execution"
        severity = 6
    strings:
        $hex  = /\$[a-z]+=\s*"(\\x[0-9a-fA-F]{2}){4,}"/
        $eval = "eval("
    condition:
        $hex and $eval
}

rule PHP_Obfuscation_Urldecode {
    meta:
        description = "urldecode used to hide payload"
        severity = 6
    strings:
        $obf = /urldecode\s*\(\s*'(%[0-9a-fA-F]{2})+'\s*\)/
    condition:
        $obf
}

rule PHP_Obfuscation_Preg_Replace_E {
    meta:
        description = "preg_replace with /e modifier for code execution"
        severity = 9
    strings:
        $s = /preg_replace\s*\(\s*['"]\/.*\/e['"]/
    condition:
        $s
}

rule PHP_Obfuscation_Variable_Function {
    meta:
        description = "Variable used as function name to hide exec"
        severity = 7
    strings:
        $varfunc = /\$[a-zA-Z_]+\s*=\s*['"](\bsystem\b|\bexec\b|\bpassthru\b|\bshell_exec\b)['"]/
    condition:
        $varfunc
}
