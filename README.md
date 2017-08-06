# About
This tool is an extension around SignTool to call into Azure Key Vault for the signing. 

## Set up
You will need several things to develop/debug this.

1.	You need an azure key vault and a client id/secret for a credential that can access it. Directions to set that up are here https://github.com/onovotny/RSAKeyVaultProvider, along with a link to a GUI tool for Key Vault that makes it easy to upload a code signing certificate
2.	You’ll need to set `KeyVaultSigner` as the startup project and use the following command line arguments (certain params are sensitive, so don’t check it in...it would be in the .user file that's ignored!)
    
    `sign "C:\Program Files (x86)\Windows Kits\10\bin\10.0.15063.0\x64\SignTool.exe" "C:\dev\signtest\signed\winqual.exe" "sign /tr http://timestamp.digicert.com /fd sha256 /td sha256 /dlib C:\dev\KeyVaultSignToolWrapper\KeyVaultSigner\bin\Debug\x64\KeyVaultSigner.dll" -kvu https://<keyVaultname>.vault.azure.net/ -kvc <key vault certificate name> -kvi <client id> -kvs <client secret>`
i.	Make sure you update the `/dlib` path to wherever matches your local disk. Same with the `winqual.exe` parameter. Choose some unsigned dll that you’ll have signed
3.	Install the child process debugging tool (needed to follow the flow): https://marketplace.visualstudio.com/items?itemName=GreggMiskelly.MicrosoftChildProcessDebuggingPowerTool
