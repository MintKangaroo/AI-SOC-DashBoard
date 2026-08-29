/*
 * SOC 대시보드 기본 YARA 룰
 *
 * 해시 대조(hash_checker)는 '알려진 그 파일'만 잡는다 — 한 바이트만 바뀌어도
 * 놓친다. YARA 는 내용 패턴으로 잡으므로 변종에 강하다. 둘은 대체가 아니라 보완이다.
 *
 * meta.mitre 는 커버리지 자가 진단(modules/coverage.py)이 읽는다.
 * 각 룰의 정탐/오탐 샘플은 data/yara/rule_tests.yml 에 있고 CI 가 검증한다.
 */

rule SOC_EICAR_Test_File
{
    meta:
        description = "EICAR 표준 안티바이러스 테스트 문자열 (악성 아님, 배선 검증용)"
        author = "SOC Dashboard"
        severity = "LOW"
        mitre = "T1204"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule SOC_PHP_Webshell
{
    meta:
        description = "PHP 웹셸 — 사용자 입력을 그대로 실행하는 패턴"
        author = "SOC Dashboard"
        severity = "CRITICAL"
        mitre = "T1505"
    strings:
        $php  = "<?php"
        $exec1 = "eval("  nocase
        $exec2 = "system(" nocase
        $exec3 = "passthru(" nocase
        $exec4 = "shell_exec(" nocase
        $input1 = "$_POST"
        $input2 = "$_GET"
        $input3 = "$_REQUEST"
    condition:
        $php and any of ($exec*) and any of ($input*)
}

rule SOC_Reverse_Shell_Script
{
    meta:
        description = "스크립트 형태의 리버스 셸 (bash /dev/tcp · python socket)"
        author = "SOC Dashboard"
        severity = "CRITICAL"
        mitre = "T1059"
    strings:
        $bash_tcp   = "/dev/tcp/"
        $bash_i     = "bash -i"
        $py_sock    = "socket.socket("
        $py_dup     = "os.dup2("
        $py_shell   = "pty.spawn("
        $nc_e       = "nc -e "
    condition:
        ($bash_tcp and $bash_i) or ($py_sock and $py_dup and $py_shell) or $nc_e
}

rule SOC_Cryptominer_Artifact
{
    meta:
        description = "크립토마이너 바이너리·설정 — 채굴 풀 접속 문자열"
        author = "SOC Dashboard"
        severity = "HIGH"
        mitre = "T1496"
    strings:
        $pool1 = "stratum+tcp://"
        $pool2 = "stratum+ssl://"
        $pool3 = "minexmr"
        $pool4 = "supportxmr"
        $bin1  = "xmrig"
        $bin2  = "cpuminer"
    condition:
        any of ($pool*) or any of ($bin*)
}

rule SOC_UPX_Packed_ELF
{
    meta:
        description = "UPX 로 패킹된 ELF — 리눅스 악성코드가 흔히 쓰는 난독화"
        author = "SOC Dashboard"
        severity = "MEDIUM"
        mitre = "T1027"
    strings:
        $upx1 = "UPX!"
        $upx2 = "$Info: This file is packed with the UPX"
    condition:
        uint32(0) == 0x464C457F and any of ($upx*)
}

rule SOC_Curl_Pipe_Shell_Dropper
{
    meta:
        description = "원격 스크립트를 받아 바로 실행하는 드로퍼"
        author = "SOC Dashboard"
        severity = "HIGH"
        mitre = "T1105"
    strings:
        $tool1 = "curl "
        $tool2 = "wget "
        $pipe1 = "| bash"
        $pipe2 = "| sh"
        $pipe3 = "|bash"
        $pipe4 = "|sh"
    condition:
        any of ($tool*) and any of ($pipe*)
}
