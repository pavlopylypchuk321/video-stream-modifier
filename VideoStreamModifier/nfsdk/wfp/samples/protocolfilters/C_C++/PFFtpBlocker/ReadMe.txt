The command line utility PFFtpBlocker.exe blocks the transfer of files containing the specified substring to the server.

There are two filtering modes: with and without maximum file size.

For example:
PFFtpBlocker.exe test 100000 - block files with substring test less than 100000 bytes in size
PFFtpBlocker.exe test - block files of any size with substring test

In the first case, the file data is buffered on the client for validation, and only transferred to the server after the entire file has been validated.

In the second case, data is transmitted without delay. Verification occurs after the entire file has been transferred.
If the file contains the substring specified in the parameters, the data connection is terminated and the downloaded part of the file is removed from the server.

The advantage of the first case is that if the file is to be locked, nothing is stored on the server for sure.
Minus - there is a limit on the file size, because The FTP client will time out the connection if the file is too large.

In the second case, there is no buffering on the client. But the data is transferred to the server.
Whether the downloaded part of the file is deleted correctly or not depends on the server implementation and configuration. For example the access to DELE command can be restricted.

