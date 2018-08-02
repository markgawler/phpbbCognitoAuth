# AWS Cognito Authentication

## Installation

Copy the extension to phpBB/ext/mrfg/cogauth

Go to "ACP" > "Customise" > "Extensions" and enable the "AWS Cognito Authentication" extension.

## Tests and Continuous Integration

We use Travis-CI as a continuous integration server and phpunit for our unit testing. See more information on the [phpBB Developer Docs](https://area51.phpbb.com/docs/dev/31x/testing/index.html).
To run the tests locally, you need to install phpBB from its Git repository. Afterwards run the following command from the phpBB Git repository's root:

Windows:

    phpBB\vendor\bin\phpunit.bat -c phpBB\ext\mrfg\cogauth\phpunit.xml.dist

others:

    phpBB/vendor/bin/phpunit -c phpBB/ext/mrfg/cogauth/phpunit.xml.dist

## License

[GPLv2](license.txt)
