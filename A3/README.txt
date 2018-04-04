trace.py


Raymond Wang
V00802086


Notes:

- This program is developed on MacOS High Sierra 10.13.3, Python 3.6.2 environment.

- This program requires pcapy module.
	* Open Terminal and run: % pip install pcapy

- For more info about pcapy, please visit its project site.
	* https://www.coresecurity.com/corelabs-research/open-source-tools/pcapy

- This program works fine with .pcap and .pcapng format file on my environment.
	* If you open a .pcapng file and get error message
	* Please use Wireshark to transform the .pcapng file into .pcap format


R1 Instruction:

- Unzip the "361A3.zip" file.

- Have trace.py and the captured files on the same folder.

- Run the code by input the following string in the console:
	* % python trace.py <filename>
	* ex. % python trace.py group1-trace1.pcap

R2:

- Please see R2.pdf