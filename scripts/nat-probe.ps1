<#
  ================================================================
  NAT 类型探测器 (IPv4)  ——  PowerShell 版, 不需要 Python
  ================================================================
  用途: 判断本机所处网络的 NAT 行为, 决定 P2P 打洞能不能成功。

  用法:
    直接双击本文件, 或:
    powershell -ExecutionPolicy Bypass -File nat-probe.ps1

  关键原理(重要):
    必须用 **同一个 UDP socket / 同一个内网源端口** 去问多个不同的公网目标。
    如果每次新建 socket, 源端口就变了, 看到的映射端口当然不同 —— 结论必然是错的。

  输出什么:
    1. 本机公网 IPv4 映射
    2. 对多个不同目标的映射端口是否一致 -> 判定 EIM(锥形) 还是 APDM(对称)
    3. 映射稳定性
    4. 是否有公网 IPv6(有的话根本不用打洞)
#>
param(
    [int]$LocalPort = 45678,
    [int]$TimeoutSec = 3
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ---------- STUN 目标(尽量分散在不同 AS) ----------
$TARGETS = @(
    @{ Name = 'Google-1';    Host = 'stun.l.google.com';    Port = 19302 }
    @{ Name = 'Cloudflare';  Host = 'stun.cloudflare.com';  Port = 3478  }
    @{ Name = 'Nextcloud';   Host = 'stun.nextcloud.com';   Port = 443   }
    @{ Name = 'Xiaomi';      Host = 'stun.miwifi.com';      Port = 3478  }
    @{ Name = 'Antisip-NL';  Host = 'stun.antisip.com';     Port = 3478  }
    @{ Name = 'Epygi-US';    Host = 'stun.epygi.com';       Port = 3478  }
    @{ Name = 'Voiparound';  Host = 'stun.voiparound.com';  Port = 3478  }
    @{ Name = 'Voipbuster';  Host = 'stun.voipbuster.com';  Port = 3478  }
)

function Invoke-StunQuery {
    param(
        [System.Net.Sockets.UdpClient]$Udp,
        [string]$TargetIp,
        [int]$TargetPort,
        [int]$Timeout
    )

    # 构造 STUN Binding Request (20 字节)
    $txn = New-Object byte[] 12
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($txn)
    $pkt = New-Object byte[] 20
    $pkt[0] = 0x00; $pkt[1] = 0x01                  # Binding Request
    $pkt[2] = 0x00; $pkt[3] = 0x00                  # 长度 0
    $pkt[4] = 0x21; $pkt[5] = 0x12; $pkt[6] = 0xA4; $pkt[7] = 0x42   # magic cookie
    [Array]::Copy($txn, 0, $pkt, 8, 12)

    try {
        $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($TargetIp), $TargetPort)
        [void]$Udp.Send($pkt, 20, $remote)
    } catch {
        return $null
    }

    $deadline = (Get-Date).AddSeconds($Timeout)
    $Udp.Client.ReceiveTimeout = [int]($Timeout * 1000)

    while ((Get-Date) -lt $deadline) {
        try {
            $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $data = $Udp.Receive([ref]$ep)
        } catch {
            return $null
        }
        if ($data.Length -lt 20) { continue }
        $mtype = ([int]$data[0] -shl 8) -bor [int]$data[1]
        if ($mtype -ne 0x0101) { continue }                       # 必须 Binding Success
        if (-not ($data[4] -eq 0x21 -and $data[5] -eq 0x12 -and $data[6] -eq 0xA4 -and $data[7] -eq 0x42)) { continue }

        $match = $true
        for ($i = 0; $i -lt 12; $i++) { if ($data[8 + $i] -ne $txn[$i]) { $match = $false; break } }
        if (-not $match) { continue }

        $mlen = ([int]$data[2] -shl 8) -bor [int]$data[3]
        $pos = 20
        $end = [Math]::Min(20 + $mlen, $data.Length)
        while ($pos + 12 -le $end) {
            $atype = ([int]$data[$pos] -shl 8) -bor [int]$data[$pos + 1]
            $alen  = ([int]$data[$pos + 2] -shl 8) -bor [int]$data[$pos + 3]
            if ($atype -eq 0x0020 -and $alen -ge 8 -and $data[$pos + 5] -eq 0x01) {
                $mport = (([int]$data[$pos + 6] -shl 8) -bor [int]$data[$pos + 7]) -bxor 0x2112
                $ipInt = ([uint32]$data[$pos + 8] -shl 24) -bor ([uint32]$data[$pos + 9] -shl 16) `
                       -bor ([uint32]$data[$pos + 10] -shl 8) -bor [uint32]$data[$pos + 11]
                $ipInt = $ipInt -bxor 0x2112A442
                $b = [BitConverter]::GetBytes($ipInt)
                [Array]::Reverse($b)
                return [PSCustomObject]@{
                    IP   = ([System.Net.IPAddress]::new($b)).ToString()
                    Port = [int]$mport
                }
            }
            $pos += 4 + $alen + ((4 - ($alen % 4)) % 4)
        }
    }
    return $null
}

function Test-GlobalIPv6 {
    foreach ($addr in @('2606:4700:4700::1111', '2400:3200::1')) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
            $iar = $c.BeginConnect($addr, 53, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(4000) -and $c.Connected) { $c.Close(); return $true }
            $c.Close()
        } catch { }
    }
    return $false
}

# ================= 主流程 =================
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  NAT 类型探测 (IPv4)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# --- 1. 绑定固定内网端口 ---
$udp = $null
try {
    $udp = New-Object System.Net.Sockets.UdpClient($LocalPort)
    Write-Host ("  使用内网端口   : {0}   (全程复用同一个 socket)" -f $LocalPort)
} catch {
    $udp = New-Object System.Net.Sockets.UdpClient(0)
    $LocalPort = $udp.Client.LocalEndPoint.Port
    Write-Host ("  使用内网端口   : {0}   (45678 被占用, 自动换的)" -f $LocalPort) -ForegroundColor Yellow
}

# --- 2. IPv6 情况 ---
$hasV6 = Test-GlobalIPv6
Write-Host ("  公网 IPv6      : {0}" -f $(if ($hasV6) { '有  (有 IPv6 的话根本不用打洞!)' } else { '无' })) -ForegroundColor $(if ($hasV6) {'Green'} else {'Gray'})

# --- 3. 逐个目标查询 ---
Write-Host ""
Write-Host "  ---- 对多个不同目标查询公网映射 ----" -ForegroundColor Yellow
$results = @()
foreach ($t in $TARGETS) {
    $ip = $null
    try {
        $ip = ([System.Net.Dns]::GetHostAddresses($t.Host) |
               Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
               Select-Object -First 1).IPAddressToString
    } catch { }
    if (-not $ip) {
        Write-Host ("    {0,-12} DNS 解析失败" -f $t.Name) -ForegroundColor DarkGray
        continue
    }
    $m = Invoke-StunQuery -Udp $udp -TargetIp $ip -TargetPort $t.Port -Timeout $TimeoutSec
    if ($m) {
        $results += [PSCustomObject]@{ Name = $t.Name; TargetIp = $ip; MapIP = $m.IP; MapPort = $m.Port }
        Write-Host ("    [OK]   {0,-12} -> {1,-16} 映射 {2}:{3}" -f $t.Name, $ip, $m.IP, $m.Port)
    } else {
        Write-Host ("    [X]    {0,-12} -> {1,-16} 无响应" -f $t.Name, $ip) -ForegroundColor DarkGray
    }
}

if ($results.Count -lt 2) {
    Write-Host ""
    Write-Host "  有效样本不足 —— 出站 UDP 可能被封锁。" -ForegroundColor Red
    Write-Host "  这种情况下打洞基本不可能, 只能走 TCP/443 的隧道方案。" -ForegroundColor Red
    $udp.Close()
    Write-Host ""
    if (-not $NoPause) { Read-Host "按回车退出" }
    exit 1
}

# --- 4. 稳定性: 对同一目标重复查询 ---
Write-Host ""
Write-Host "  ---- 映射稳定性 ----" -ForegroundColor Yellow
$stableTargetIp = $results[0].TargetIp
$repeat = @()
for ($i = 0; $i -lt 3; $i++) {
    $m = Invoke-StunQuery -Udp $udp -TargetIp $stableTargetIp -TargetPort 19302 -Timeout $TimeoutSec
    if ($m) { $repeat += $m.Port }
    Start-Sleep -Milliseconds 300
}
Write-Host ("    重复查询同一目标 3 次 -> {0}" -f ($repeat -join ', '))
$stable = (($repeat | Sort-Object -Unique).Count -le 1)
Write-Host ("    稳定性: {0}" -f $(if ($stable) { '稳定' } else { '不稳定(每次映射都在变!)' })) -ForegroundColor $(if ($stable) {'Green'} else {'Red'})

$udp.Close()

# --- 5. 判定 ---
$ips   = ($results | Select-Object -ExpandProperty MapIP | Sort-Object -Unique)
$ports = ($results | Select-Object -ExpandProperty MapPort | Sort-Object -Unique)

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  判定结果" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ("  公网 IP        : {0}" -f ($ips -join ', '))
Write-Host ("  映射端口集合   : {0}" -f ($ports -join ', '))
Write-Host ""

$verdict = ''
if ($ips.Count -gt 1) {
    $verdict = '多出口'
    Write-Host "  [!] 对不同目标出口 IP 不同 —— 存在多出口/负载均衡, 打洞会很不稳定。" -ForegroundColor Yellow
}

if ($ports.Count -eq 1) {
    Write-Host "  ★ EIM (端点无关映射 / 锥形 NAT)  —— 对打洞友好" -ForegroundColor Green
    Write-Host "    同一个内网端口对任何目标都用同一个公网端口," -ForegroundColor Green
    Write-Host "    标准的 UDP 打洞成功率很高(两端都是 EIM 时约 90%)。" -ForegroundColor Green
    $verdict = 'EIM'
} else {
    Write-Host ("  ★ APDM (映射随目标变化) = 对称 NAT  —— {0} 个不同端口" -f $ports.Count) -ForegroundColor Red
    Write-Host "    服务器看到的端口 != 对端看到的端口, 标准打洞会失败。" -ForegroundColor Red
    $seq = $results | Select-Object -ExpandProperty MapPort
    $sorted = $seq | Sort-Object
    $diffs = @()
    for ($i = 1; $i -lt $sorted.Count; $i++) { $diffs += ($sorted[$i] - $sorted[$i-1]) }
    Write-Host ("    端口序列(按查询顺序): {0}" -f ($seq -join ', '))
    Write-Host ("    排序后相邻差        : {0}" -f ($diffs -join ', '))
    if ($diffs.Count -gt 0 -and (($diffs | Sort-Object -Unique).Count -eq 1)) {
        Write-Host "    端口单调且步长固定 -> 端口预测打洞(Natter 类)理论可行。" -ForegroundColor Yellow
    } else {
        Write-Host "    端口无固定规律 -> 端口预测不可靠, 需要中继兜底。" -ForegroundColor Yellow
    }
    $verdict = 'APDM(对称NAT)'
}

# --- 6. 可粘贴的汇总 ---
Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  把下面这几行发给对方 (方便对比两端)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  机器名      : " + $env:COMPUTERNAME)
Write-Host ("  公网IPv4    : " + ($ips -join ', '))
Write-Host ("  公网IPv6    : " + $(if ($hasV6) { '有' } else { '无' }))
Write-Host ("  NAT 类型    : " + $verdict)
Write-Host ("  映射稳定性  : " + $(if ($stable) { '稳定' } else { '不稳定' }))
Write-Host ("  有效样本    : " + $results.Count + "/" + $TARGETS.Count)
Write-Host ""

if ($hasV6) {
    Write-Host "  💡 提示: 本机有公网 IPv6 —— 很可能根本不需要 IPv4 打洞!" -ForegroundColor Green
    Write-Host "     直接用 IPv6 直连会简单得多也可靠得多。" -ForegroundColor Green
    Write-Host ""
}

if (-not $NoPause) { Read-Host "按回车退出" }
