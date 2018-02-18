SmartClient.py


Raymond Wang
V00802086


Instruction:

- Unzip the "361A1.zip" file.

- Open Terminal and goto the folder directory where contains SmartClient.py file.

- Run the code by input the following string in the console:
	% python SmartClient.py <hostname>
ex.	% python SmartClient.py www.uvic.ca

- The returned result will include website, IP, support of HTTPS, port#, the newest HTTP version that the server supports, status code, and the list of cookies.
ex.	Website: www.uvic.ca
	IP: 142.104.197.120
	Support of HTTPS: YES
	Connecting over port 443...
	The newest HTTP versions that the web server supports: HTTP/1.1
	Status code: 200 - OK
	List of Cookies:	
	* name: SESSID_UV_128004, domain name: www.uvic.ca
	* name: uvic_bar, domain name: .uvic.ca
	* name: www_def, domain name: 
	* name: TS01a564a5, domain name: 
	* name: TS01c8da3c, domain name: www.uvic.ca
	* name: TS014bf86f, domain name: .uvic.ca


Notes:

- The input <hostname> should NOT include protocols(http(s)://), path(.com/abc), or any other parameters(=abc123).

- This program could NOT handle <hostname> that will redirects to another website with invalid input as described above.
ex.	www.aircanada.com
	will redirect to
	www.aircanada.com/ca/en/aco/home.html
	which could NOT be handled in this program.

- If the program stop during the connecting or redirecting step, please try again. Because some server might take a litter bit longer time to connect, and the timeout for this program is set to 1(socket.settimeout(1)).

