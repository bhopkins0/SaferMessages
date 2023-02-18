# SaferMessages

A simple web application for encrypted messaging. Built with security in mind and does not use Javascript.

Live demo: https://msg.saferspeech.com


![Demo Image](<https://raw.githubusercontent.com/bhopkins0/SaferMessages/main/Demo.png>)


It is recommended to properly configure your webserver headers as well. These are the headers I used for nginx:


        add_header Content-Security-Policy "default-src 'self'; script-src 'none'; object-src 'none';" always;
        add_header X-Frame-Options "DENY" always;
        add_header X-Xss-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubdomains" always;
        add_header Referrer-Policy "no-referrer" always;
        
       
