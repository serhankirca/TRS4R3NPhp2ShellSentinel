rule PHP_Simple_Webshell
{
    meta:
        description = "Basit PHP web shell imzası"
        author = "TRS4R3N Sentinel"
    strings:
        $a = "eval($_POST" nocase
        $b = "eval($_GET" nocase
        $c = "base64_decode($_POST" nocase
        $d = "system($_GET" nocase
        $e = "passthru($_POST" nocase
    condition:
        any of them
}