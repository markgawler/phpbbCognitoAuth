# phpBB AWS Cognito Authentication

This extension is currently under development so will contain bugs, please report them 
(or fix them and submit a pull request).

This phpBB extension provides an authentication bridge for phpBB to AWS Cognito. 
Currently, only actions on the phpBB UCP / ACP are reflected on to the AWS Cognito user
pool. 

## Why would you need this extension?

The intended use case for this extension is for a web application to share the user 
credentials of a phpBB board, thus allowing a part of a site to move to a server less 
architecture whilst retaining the legacy phpBB forum. Initially all user management,
registration is performed via the phpBB UCP/ACP.

## User Migration

Users are automatically migrated to the Cognito user pool when they first login after
the “cogauth” phpBB authentication plugin is enabled. The migration happens silently 
in the background so the use retain the same user credentials. Currently the 
password strength rules on the User Pool must be the same or less than the phpBB rules 
to allow the migration to take place otherwise users with weak passwords will not 
be migrated issue #1.  

### User Attribute Mapping

To allow usernames to change and case insensitivity for logins the mapping of phpBB 
user attributes to cognito attribute is as follows. The attribute mapping is:

| phpBB  | Cognito           |
|----------------|-------------------|
| user_id        | usename*          |
| username_clean | preferred_username |
| username       | nickname          |

[*] The username is a modified from of the phpBB user_id except when the experimental support for AWS Hosted UI is used. 

## Installation

Copy the extension to phpBB/ext/mrfg/cogauth

Go to "ACP" > "Customise" > "Extensions" and enable the "AWS Cognito Authentication" extension.

## Tests ~~and Continuous Integration~~

We use ~~Travis-CI as a continuous integration server and~~ phpunit for our unit testing. See more information on the [phpBB Developer Docs](https://area51.phpbb.com/docs/dev/31x/testing/index.html).
To run the tests locally, you need to install phpBB from its Git repository. Afterwards run the following command from the phpBB Git repository's root:

Windows:

    phpBB\vendor\bin\phpunit.bat -c phpBB\ext\mrfg\cogauth\phpunit.xml.dist

others:

    phpBB/vendor/bin/phpunit -c phpBB/ext/mrfg/cogauth/phpunit.xml.dist

## License

[GPLv2](license.txt)
