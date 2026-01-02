rule Tycoon2FA_Green_CaptchaPages
{
    meta:
        description = "Tycoon2FA Green Enabled Captcha Pages"
        author = "TiiTcHY"
        date = "02/01/2026"        
        Url = "https://axum.lofriovou.sa.com/mFLoLEpPWexi9!VFD2LGJh0/"
        source = "https://pro.urlscan.io/result/019b1abc-d370-7079-be5d-5e7c4e8764bc/dom"
    strings:
        $str1 = "Verifying your request..."
        $str2 = "Verified successfully" 
        $str3 = "tigerSpin"
        $str4 = "eagleDone "
        $str5 = "parrotMsg"
    condition:
        all of them
}