
ngx_http_knock_module
=====================

#### Summary

The port-knocking concept applied to websites. Hitting secret urls acts as a handshake to access login pages.

#### Purpose

The internet is full of bots which go around attacking and brute forcing username/password login boxes and
searching the internet for websites vulnerable to known security flaws (the webmaster hasn't had time to
update) or zero-day exploits where no upgrade to a safe version is possible.

As well as frequently destroying sites, they fill the logs with failures and obsecure useful authentication
records.

The issues are common against the SSH protocol. Automated bots networks scan the internet trying to brute force
access to machines.	Whilst client certificates provide protection they remove the ability to log in from anywhere.
fail2ban is another good solution that can stop an attack by an individual machine. After those security measures,
port-knocking (where a secret agreed shake of packets are sent to a machines' ports to open the ssh port) is powerful
ally.

This module takes that secret-handsake approach and applies it to websites. If you're hosting any of a dozen
host-your-own projects such as roundmail, mysql web client, and you want to take extra steps to secure yourself
ngx_http_knock_module can provide that.

#### Demonstration

A demonstration of the [video is available here](https://www.youtube.com/watch?v=85Im_LfV2jQ).

#### Installation

Download the nginx software to your machine and unpack it. Download and untar the software from this github repo.
Add the software to nginx during the configure stage by using this argument:

	./configure --add-module=<download path>/ngx_http_knock_module

	# continue normal nginx installation
	make
	make install

#### Directives

The following new directives are available in your nginx configurations

	knock_enabled
		
		states whether the website should be protected by the module.
		type: flag (value values: on / off)
	
	knock_uri

		a string with the secret path in it.
		type: uri (must be part of the location in order to be processed)
		accepted multiple times
		note: that key/value parameters cannot form part of the secret.

#### Directives in an example:

    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {

            knock_enabled on;
            knock_uri /hello;
            knock_uri /come/and/get/some;
            knock_uri /yeah/but/did/you/guess/this;

            root   html;
            index  index.html index.htm;
        }

    }

In the example above, if a user ties to hit the root of a website they get "404 not found". if they hit
/hello, they get 404 not found. if they try /come/and/get/some they also get "404 not found". If they
then try /yeah/but/did/you/guess/this, they still get a 404. Then when they return to the root again,
the website is served up as they have completed the secret handshake. Most bots wouldn't waste their
time trying to second guess those urls in the hope the server is listening!

#### Notes

* knock_uris must be hit in the sequence specified.
* knock_uris have to pass through the nginx server obviously
* uris that aren't a part of the knock sequence do not reset the person's place in the knock sequence.
* the module is limited to 30,000 ips. change the #define line to increase or decreate this value.
* this module was written against nginx 1.2.1

Enjoy

Phillip Taylor
August 17th 2014.
