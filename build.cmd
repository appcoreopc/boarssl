echo "Twrch..."
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:Twrch.exe /main:Twrch Asn1\*.cs Crypto\*.cs SSLTLS\*.cs X500\*.cs XKeys\*.cs Twrch\*.cs

echo "TestCrypto..."
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:TestCrypto.exe /main:TestCrypto Tests\*.cs Asn1\*.cs Crypto\*.cs SSLTLS\*.cs X500\*.cs XKeys\*.cs ZInt\*.cs
