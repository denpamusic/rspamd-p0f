# rspamd-p0f

> :warning: **This plugin is** now part of rspamd and it's development has been **discontinued**.  
> If you encounter any problems, feel free to report issues or submit PRs directly to the main [rspamd repository](https://github.com/rspamd/rspamd).

This lua plugin provides passive OS fingerprinting feature for [rspamd](https://github.com/rspamd/rspamd) filtering system via [p0f v3](https://github.com/p0f/p0f) fingerprinter. This allows to (somewhat inaccurately) detect which operating system running on remote server and what type of connection it's using. This information can then be used as an additional factor in detecting infected PCs and botnets.

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
![P0F symbol](https://user-images.githubusercontent.com/16575433/64826636-f8c03680-d5c9-11e9-86fc-b0ab1eda7ee4.png)

Plugin can be configured by editing following settings in `/etc/rspamd/local.d/p0f.conf` _(must be created first)_
```
# Path to the unix socket that p0f listens on
socket = '/tmp/p0f.sock';

# Connection timeout
timeout = 10;

# If defined, insert symbol with lookup results
symbol = 'P0F';

# If defined, insert header with lookup results with following format:
# "$OS (up: $UPTIME min), (distance $DISTANCE, link: $LINK), [$IP]"
header = false;

# Patterns to match OS string against
patterns = {
  WINDOWS = '^Windows.*';
}

# Cache lifetime in seconds (default - 2 hours)
expire = 7200;

# Cache key prefix
key_prefix = 'p0f';
```
