$f = Get-ChildItem 'D:\MySecBook\security-kb' -Recurse -Filter '07*.md' | Where-Object { $_.Name -like '*UAC*' }
if (-not $f) { Write-Output 'FILE NOT FOUND'; exit }
$c = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8
$cjk = [regex]::Matches($c, '[\u4e00-\u9fff]').Count
$nws = ([regex]::Replace($c, '\s', '')).Length
$lines = (Get-Content -LiteralPath $f.FullName -Encoding UTF8).Count
Write-Output ('Found file')
Write-Output ('Lines: ' + $lines)
Write-Output ('CJK chars: ' + $cjk)
Write-Output ('Non-whitespace chars: ' + $nws)