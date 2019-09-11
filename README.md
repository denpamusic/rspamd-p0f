# rspamd-p0f

This lua plugin provides passive OS fingerprinting feature for [rspamd](https://github.com/rspamd/rspamd) filtering system via [p0f v3](https://github.com/p0f/p0f) fingerprinter. This allows to (somewhat inaccurately) detect which operating system running on remote server and what type of connection it's using. This information can then be used as an additional factor in detecting infected PCs and botnets.

>:warning: As of now, usage of this plugin in high to medium load mail systems is strongly discouraged due to having no result caching whatsoever (will be implemented later via rspamd_redis)


## Running p0f with API support
To make p0f listen to API requests on unix socket, you will need to run it with `-s file` flag set:  
```bash
p0f -c "/tmp/p0f.sock" "tcp dst port 25"
```
This way p0f will be monitoring port 25 for new connections to fingerprint and listening to requests on `/tmp/p0f.sock` socket with at max 20 connections (can be adjusted using `-S limit` flag).

For FreeBSD you can also use rc script provided in __freebsd__ directory. Move file named p0f to `/usr/local/etc/rc.d` on your system, then you can start p0f as regular service.
```
echo 'p0f_enable="YES"' | sudo tee /usr/local/etc/rc.conf.d/p0f > /dev/null
service p0f start
```

## Plugin installation
Move all files from __rspamd__ directory of this repository to your rspamd configuration directory (e. g. `/etc/rspamd` on Debian or `/usr/local/etc/rspamd` on FreeBSD) and reload rspamd.

To make sure that everything works, look for P0F symbol in message scan results or X-OS-Fingerprint header:
![P0F symbol](https://user-images.githubusercontent.com/16575433/64662404-056d4f00-d451-11e9-9f53-945147e3802e.png)

Plugin can be configured by editing following settings in `/etc/rspamd/local.d/p0f.conf` _(must be created first)_
```lua
p0f {
  # Path to the unix socket that p0f listens on
  socket = '/tmp/p0f.sock';

  # Connection timeout
  timeout = 10;

  # If defined, insert symbol with lookup results
  symbol = 'P0F';

  # If defined, insert header with lookup results
  header = 'X-OS-Fingerprint';
}
```
