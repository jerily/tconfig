# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

proc aws { args } {
    return [exec aws --profile localstack {*}$args]
}

proc set_ssm_params { params } {
    foreach { key value type } $params {
        set outcome [aws ssm put-parameter --name $key --value $value --type $type --overwrite --output text]
        if { ![string is integer -strict $outcome] } {
            return -code error "something wrong when setting the parameter \"$key\" to\
                the value \"$value\": $outcome"
        }
    }
}

proc unindent { text } {
    set text [string trim $text \n]
    return [join [lmap x [split $text \n] { string trimleft $x }] \n]
}

proc aws_seed { } {

    if { [info exists ::aws_seed] } return

    # Make sure the aws cli can use profile localstack
    if { [catch { aws configure get endpoint_url 2>@1 } err] } {
        aws configure set endpoint_url "http://localhost:4566"
        aws configure set region "eu-west-1"
        aws configure set aws_access_key_id "test"
        aws configure set aws_secret_access_key "test"
    }

    # Set sample parameters in localstack
    set_ssm_params {
        /dev/db/password     "dev-password"        "SecureString"
        /dev/db/hostname     "dev-hostname"        "String"
        /dev/email/password  "dev-email-password"  "SecureString"
        /prod/db/password    "prod-password"       "SecureString"
        /prod/db/hostname    "prod-hostname"       "String"
        /prod/email/password "prod-email-password" "SecureString"
    }

    # Create a KMS key
    set ::kms_key [aws kms create-key --output text --query "KeyMetadata.Arn"]

    # The default configuration
    set ::default_config_file [unindent {
        # test comment

        # ^ empty line
        [db]
        somekey = untoched
        password = foo
        hostname = baz

        [email]
        password = qux
    }]

    set ::aws_seed 1

}

proc tcltest::cleanupTestsHook { } {
    if { ![info exists ::aws_seed] } return
    # Cleanup
    aws kms schedule-key-deletion --key-id $::kms_key --pending-window-in-days 7
}
