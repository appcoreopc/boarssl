#! /bin/sh

CSC=$(which mono-csc || which dmcs || which mcs || echo "none")

if [ $CSC = "none" ]; then
	echo "Error: please install mono-devel."
	exit 1
fi

set -e

echo "TestCrypto..."
$CSC /out:TestCrypto.exe /main:TestCrypto Tests/*.cs Asn1/*.cs Crypto/*.cs SSLTLS/*.cs X500/*.cs XKeys/*.cs ZInt/*.cs

#echo "Client..."
#$CSC /out:Client.exe /main:Client Asn1/*.cs Crypto/*.cs SSLTLS/*.cs X500/*.cs XKeys/*.cs Client.cs

#echo "Server..."
#$CSC /out:Server.exe /main:Server Asn1/*.cs Crypto/*.cs SSLTLS/*.cs X500/*.cs XKeys/*.cs Server.cs

echo "Twrch..."
$CSC /out:Twrch.exe /main:Twrch Asn1/*.cs Crypto/*.cs SSLTLS/*.cs X500/*.cs XKeys/*.cs Twrch/*.cs
