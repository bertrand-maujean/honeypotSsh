# Yet another SSH Honeypot


## Why
I was using Cowrie, but get blocked by a bizarre issue. All recording from outside my local net were empty. 
The hash which serve as a filename was the hash of a empty byte string. So I wrote this SSH shell recorder.

## How
In the sshd_config, point "honeypotSsh" using "ForceCommand" directive.
The program will record every read/write operation
Every argc/argv is transparently forwarded
Invoke the $SHELL shell.
The "replay" program is used to whatb it's name says.

## TODO 
- logging is on stdout, should be settable to a ad hoc file
- recording is statically configuration to /tmp, should be configurable
- Replay should be smarted : aggregating message and corresponding echo, aggregating related in/out messages
- Replay : simulate what is shown on screen
- Replay : print messages at real or controlled speed
- Implement link with auditd, using some session id or user id, and incorporate this source of info in the record 

## Licence
This work is released under 
**GNU AFFERO GENERAL PUBLIC LICENSE Version 3, 19 November 2007** 
by
**Bertrand Maujean** 
See : http://www.gnu.org/licenses/agpl.html and file LICENSE.txt in distribution folder.
                       
