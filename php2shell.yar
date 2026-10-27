rule PHP2Shell_Config_RCE_Payload
{
    meta:
        description = "Detects PHP2Shell configuration exploit payloads and webshell signatures"
        author = "TRS4R3N Sentinel"
        severity = "Critical"
        mitre_attack = "T1505.003"
        cve = "CVE-2026-109618"
    strings:
        $tag_php2shell = "php2shell" ascii nocase
        $eval_pattern = "eval(" ascii nocase
        $decode_pattern = "base64_decode" ascii nocase
        $rce_param = "cmd=" ascii nocase
    condition:
        $tag_php2shell or ($eval_pattern and $decode_pattern and $rce_param)
}