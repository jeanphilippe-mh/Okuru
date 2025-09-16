# Okuru
**送る(Okuru, "to send")** is a [snappass](https://github.com/pinterest/snappass) **fork/reimplementation in Golang** with the echo web framework adding API (for Password only at the moment) and File upload.

You can use it to temporary store safely password(s) and file(s).

## Security

Passwords are encrypted using **Fernet symmetric encryption** from the cryptography library. A random unique key is generated for each password and is never stored.
It is rather sent as part of the password link. 

This means that even if someone has access to the Redis store, the passwords are still safe.

## Requirements

* You can use **Debian 13** "Trixie" (https://www.debian.org/CD/http-ftp/).
* Redis package with **notify-keyspace-events KEA** set on redis.conf.
* Golang (I've used latest **1.25** from arm64/linux with Go Modules)

## Installation/How to use it

* wget https://go.dev/dl/go1.25.0.linux-arm64.tar.gz
* tar -xvf go1.25.0.linux-arm64.tar.gz
* mv go /usr/local
* echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
* **git clone** the repository
* cd Okuru
* **go mod init** github.com/jeanphilippe-mh/Okuru
* **go get** in the directory

To test :
* Drop the **cert.pem** and **key.pem** files in /Okuru directory. This is a mandatory to start HTTPS server.
* Copy the .env.dist file to .env file or edit it with your configuration. 
* Source it (``set -a && source .env && set +a`` for example on linux).
* **go build** and run ./Okuru .

## Configuration

You can configure the following via environment variables.

**NO_SSL**: if you are not using SSL/HTTPS. This will affect the URL that are generated.

**REDIS_HOST**: this should be set by Redis, but you can override it if you want. Defaults to "localhost".

**REDIS_PORT**: is the port redis is serving on, defaults to 6379.

**REDIS_DB**: is the database that you want to use on this redis server. Defaults to db 0.

**REDIS_PREFIX**: (optional, defaults to "okuru_") prefix used on redis keys to prevent collisions with other potential clients.

**REDIS_URL**: (optional) will be used instead of REDIS_HOST, REDIS_PORT, and SNAPPASS_REDIS_DB to configure the Redis client object. For example: redis://username:password@localhost:6379/0

**OKURU_APP_PORT**: (optional) the port on which the app will run.

**OKURU_TOKEN_SEPARATOR**: The token that will separate the keys in the URL. You might not need to change this. It defaults to "~".

**OKURU_DISCLAIMER**: If you want/need to display a disclaimer at the bottom of the page, add this. This can be html but need to be inline in this file. If you want only text, use \n to add breakline.

**OKURU_COPYRIGHT**: If you want/need to display a copyright at the bottom of the page, add this. This can be html but need to be inline in this file.

**OKURU_LOGO**: If you want to use a logo, put it in public/images/ and provide the relative path of the logo to this point. The height is arbitrary set to 45px height.

**OKURU_APP_NAME**: The name of the application.

**OKURU_FILE_FOLDER**: The folder that will be used to store the uploaded files. It can be a relative or an absolute path. It defaults to **data/**.

## Credits

* [Pinterest's snappass](https://github.com/pinterest/snappass) for the original software and idea.
* [Labstack's Echo framework](https://github.com/labstack/echo) for the web framework.
* [flosch/pongo2](https://github.com/flosch/pongo2) for the template renderer.
* [eraffaelli](https://github.com/eraffaelli/Okuru) for the goland fork/reimplementation.

## LICENCE

[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/labstack/echo/master/LICENSE)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



