# IP-Visualiser

Code:

Capture Thread - captures all frames being set to and from the network interface. Once ~100 packets are captured, create a digest thread and pass packets
Digest Threads - Parses all packets, recording relevant information into storage files. Onces done, quit
Present Threads - Web server that produces content based of findings of the digest threads
