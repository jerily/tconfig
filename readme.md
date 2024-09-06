# tconfig

This package provides secure and encrypted storage of configuration files.

## Prerequisites

- [tink-tcl](https://github.com/jerily/tink-tcl) (version 20240704.0 and above)
- [aws-sdk-tcl](https://github.com/jerily/aws-sdk-tcl) (version 1.0.10 and above)

## Installation

```bash
# It installs to /usr/local/lib
# To install elsewhere, change the prefix
# e.g. make install PREFIX=/path/to/install
make install
```

## Usage

* **::tconfig::encrypt_config** *option_dict*
    - processes the specified ini-formatted configuration file and attempts to retrieve each key from AWS SSM parameters. According to the information in AWS SSM about each key, its value will be replaced according to these rules:
      - if it does not exist in AWS SSM parameters, its value will be left as is
      - if it exists in AWS SSM parameters and its type is not `SecureString`, its value will be replaced by the value of the corresponding AWS SSM parameter
      - if it exists in AWS SSM parameters and its type is `SecureString`, then its value will be replaced by the encrypted value of the corresponding AWS SSM parameter
    - saves the processed configuration file under its original name
    - *option_dict* is a dictionary with the following keys:
      - *environment* (required) - name of the environment for which the encrypted configuration file is prepared (for example: `dev`, `prod`, `staging`)
      - *aws_kms_key* (required) - AWS KMS key identifier that will be used to encrypt the encryption key
      - *config_file* (required) - configuration file for processing
      - *aws_profile* (optional) - name of the AWS profile that will be used to access AWS services
      - *application* (optional) - optional application identifier
    - for simplified use of this command, the `tconfig-encrypt.tcl` script will be installed in the `/usr/local/bin` directory.

* **::tconfig::load_config** *ini_file* *?aws_profile?*
    - loads the specified encrypted configuration file and decrypts its values
    - *ini_file* - encrypted configuration file for processing
    - *aws_profile* - name of the AWS profile that will be used to access AWS services

## Example

Prepare a configuration file in ini-format. For example:

```
[db]
somekey = untouched
password = foo
hostname = baz

[email]
password = qux

```

Set values in AWS SSM using the following parameter name format:

```
/<environment>/<section in ini-file>/<key in ini file>
```

For example, we want to provide an environment-specific plaintext value for the `hostname` key in the `db` section and encrypted values for the `password` keys in the `db` and `email` sections. This can be done by using the following AWS CLI commands:

```shell
# these values are for the environment: dev
$ aws ssm put-parameter --name "/dev/db/hostname" --value 'dev.db.company.org' --type String
$ aws ssm put-parameter --name "/dev/db/password" --value 'dev-db-pass123' --type SecureString
$ aws ssm put-parameter --name "/dev/email/password" --value 'dev-email-pass123' --type SecureString

# these values are for the environment: prod
$ aws ssm put-parameter --name "/prod/db/hostname" --value 'prod.db.company.org' --type String
$ aws ssm put-parameter --name "/prod/db/password" --value 'prod-db-pass123' --type SecureString
$ aws ssm put-parameter --name "/prod/email/password" --value 'prod-email-pass123' --type SecureString
```

We also need the AWS KMS key to encrypt the encryption key. It can be generated by using AWS CLI command `aws kms create-key`. For example:

```shell
$ aws kms create-key --output text --query "KeyMetadata.Arn"
```

The result of this command is the ARN of the AWS KMS key that can be specified as parameter *aws_kms_key* to **::tconfig::load_config**.

Now we have everything we need to generate an encrypted configuration file. The `tconfig-encrypt.tcl` script can be used for this purpose. For example, this can be used to create an encrypted configuration file for `dev` environment:

```shell
$ tclsh /usr/local/bin/tconfig-encrypt.tcl -environment dev -aws_kms_key <ARN for AWS KMS key> /path/to/config.ini
```

The generated encrypted file can be used in the application after it has been loaded and decrypted. For example:

```tcl
package require tconfig::decrypt

set config_dict [::tconfig::load_config "/path/to/config.ini" "my_aws_profile"]

puts "Loaded configuration values: $config_dict"
```
