echo "TestCrypto..."
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:TestCrypto.exe /main:TestCrypto Tests\*.cs Asn1\*.cs Crypto\*.cs SSLTLS\*.cs X500\*.cs XKeys\*.cs ZInt\*.cs

echo "Client..."
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:Client.exe /main:Client Asn1\*.cs Crypto\*.cs IO\*.cs SSLTLS\*.cs X500\*.cs XKeys\*.cs CLI\Client.cs

echo "Twrch..."
%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:exe /out:Twrch.exe /main:Twrch Asn1\*.cs Crypto\*.cs IO\*.cs SSLTLS\*.cs X500\*.cs XKeys\*.cs Twrch\*.cs

