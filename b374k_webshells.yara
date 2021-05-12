rule b374k_webshells
{
    meta:
        author = "Matthew Russett"
        description = "This rule is looking for the b374k webshell and other webshells/tools used with it"
    strings:
		$Injector_1 = "ada yang inject"
		$Injector_2 = " IP Injector= "
		$Injector_3 = "diKi Simple Shell Injectionz"
		$Shell_1 = "Shell = Bispak"
		$Shell_2 = "Shell = Kontol"
		$Shell_3 = "MildNet - Shell"
		$Shell_4 = "UnKnown - Simple Shell"
		$Shell_5 = "b374k 2.8"
		$Shell_6 = "b374k shell : connected"
		$Shell_7 = " bind and reverse shell"
		$Shell_8 = "http://code.google.com/p/b374k-shell"
		$Shell_9 = "default password : b374k "
		$Shell_10 = "_COOKIE['b374k']"
		$Bad_guy_1 = "vir.lin90@gmail.com"
		$Bad_guy_2 = "injectortarget@gmail.com"
		$Bad_guy_3 = "Jayalah Indonesiaku"
		$Bad_guy_4 = "arch_fajri - lampungcarding - chandra35 - singkong"
		$Decoder_1 = "(gzinflate(str_rot13(base64_decode("
		$Decoder_2 = "(gzinflate(base64_decode("
		$Decoder_3 = "\x65\x76\x61\x6C\x28\x67\x7A\x69\x6E\x66\x6C\x61\x74\x65\x28\x62\x61\x73\x65\x36\x34\x5F\x64\x65\x63\x6F\x64\x65\x28"
		$Malicious_domain_1 = "irc.bandarlampung.us"
		$Malicious_domain_2 = "www.bandarlampung.us/irc/"
		$Malicious_domain_3 = "irc.mildnet.net"
    condition:
        any of them
}
