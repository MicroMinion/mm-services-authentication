# mm-services-authentication

Service to manage trust-establishment protocol between two [MicroMinion](https://github.com/MicroMinion/mm-platform) nodes

This service runs as a regular MicroMinion service and provides an out-of-band acquired security code to a remote node. The remote node will confirm this security code when correct (or send error when incorrect).

Use cases include:

* Scanning of QR code with publicKey and security code of other node embedded into it
* Manual entering of shortened publicKey and security code in application
* Emailing or sending publicKey and security code through other mechanism with link that opens application for processing

## Function calls

#### startSession()

Starts a new authentication session (only one can exist at the same time). This is to ensure that authentication can only happen when both parties put themselves in authentication mode. (e.g., by going to 'add a friend' screen of an app)

startSession generates a new security token.

#### extendSession()

Every authentication session expires after 10 seconds and needs to be manually extended. Maximum time for an authentication session is 5 minutes.

#### getToken()

Retrieves current security token as string.

#### authenticate(publicKey, securityToken)

Authenticate by providing security token and publicKey of remote node. This function call will send AUTH request to remote node.

#### event: authResult(err, result)

Generates an event with two parameters: err and result.

If err is set, an authentication error occured.

If result is set, it contains the publicKey of the remote node that we succesfully established trust with. This can be the result of either a AUTH request we received or a AUTH_RESULT request

## Messaging API

### Published messages

#### authentication.auth

#### authentication.authResult
