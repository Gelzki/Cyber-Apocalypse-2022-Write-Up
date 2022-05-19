# Misc Challenges
---
## Compressor
Let's connect to the IP using netcat.

![[Pasted image 20220517190848.png]]

Let's first try the functionality to check how it works.

We have created an artifact called test.

![[Pasted image 20220517190941.png]]

We list the directory and try to read the contents using read artifact.

![[Pasted image 20220517191010.png]]

By using the functionality **'3. Read artifact'** we have the control what file to read. We can try to use directory traversal and read contents of flag.txt, let's assume that flag.txt is on the '/' directory.

![[Pasted image 20220517191223.png]]

We got the flag.


---
