# censys_io

## about

Censys IO is an interactive Python script used to query the Censys IO API. The tool was
written with the hopes of assisting penetration testers during various engagements,
specifically those which would require attacking systems within external network environments.
The ability to passively collect information that would normally be the result of active scanning
provides a useful and much more silent approach to the initial phases of an attack.

## design

Censys IO was designed with several things in mind. Currently, the code is not completely written
the way I would like. There are many areas within the code where things became a little erratic, simply
for the sake of getting something to work, and are apart of the todo's for this project. My end goal,
however, was to have a tool which could do/have the following:

- An interactive command shell/console-like interface.
- The ability to integrate tools to perform targeted active scanning by utilizing the data which was
collected passively.
- The ability to store and access data in a simple way.
- The ability to use actively collected fingerprint data that could be parsed and correlated with
locally cached exploit code via ExploitDB/searchsploit.
- The ability to parse various types of code and normalize it into unique and easily readable data,
while collecting metrics on all aspects of the raw data. For instance, if you look up the open ports for
every host in the current console session's domain, you would be able to see a unique list of ports for
each domain. However, viewing the stored metrics can tell you how many instances of one port were found (or
basically how many hosts have that port open, among other things such as the total number of hosts in the 
current console session's scope).
- The ability to utilize the search, view, and query API endpoints.
- The ability to generate a report from a session file.



## usage

## todo
