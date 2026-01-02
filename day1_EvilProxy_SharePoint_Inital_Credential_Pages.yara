rule EvilProxy_SharePoint_Inital_Credential_Pages
{
    meta:
        description = "Detects EvilProxy fake Sharepoint Inital Credential Pages"
        author = "TiiTcHY"
        source = "https://www.virustotal.com/gui/url/02176d1d1b506b58cca2d51036fc4c355b5feaae1ab8dae75850013a381d7cb4/content/source"

    strings:
        $decodeA = "decodeUrlWithKey" 
        $decodeB = "decodeUrl" 
        $title = "<title>SharePoint</title>" 
        $check = "check_email.php" 
        $h1title = "Microsoft SharePoint" 

    condition:
        $title and $check and $h1title and ($decodeA or $decodeB)
}