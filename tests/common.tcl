# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

proc aws { args } {
    lappend args "--endpoint-url=http://localhost:4566"
    return [exec aws {*}$args]
}

proc set_ssm_params { params } {
    foreach { k v } $params {
        set ::env(AWS_ACCESS_KEY_ID) "test"
        set ::env(AWS_SECRET_ACCESS_KEY) "test"
        set ::env(AWS_DEFAULT_REGION) "eu-west-1"
        set outcome [aws ssm put-parameter --name $k --value $v --type String --overwrite --output text]
        if { ![string is integer -strict $outcome] } {
            return -code error "something wrong when setting the parameter \"$k\" to\
                the value \"$v\": $outcome"
        }
    }
}

proc unindent { text } {
    set text [string trim $text \n]
    return [join [lmap x [split $text \n] { string trimleft $x }] \n]
}

proc aws_seed { } {

    if { [info exists ::aws_seed] } return
    set ::aws_seed 1

    # Set sample parameters in localstack
    set_ssm_params {
        /dev/db/password "dev-password"
        /dev/db/hostname "dev-hostname"
        /dev/email/password "dev-email-password"
        /prod/db/password "prod-password"
        /prod/db/hostname "prod-hostname"
        /prod/email/password "prod-email-password"
    }

    # Create a KMS key
    set ::kms_key [aws kms create-key --output text --query "KeyMetadata.Arn"]

    # The default configuration
    set ::default_config_file [unindent {
        # test comment

        # ^ empty line
        [db]
        somekey = untoched
        encrypt:password = foo
        plain:hostname = baz

        [email]
        encrypt:password = qux
    }]

}

proc tcltest::cleanupTestsHook { } {
    if { ![info exists ::aws_seed] } return
    # Cleanup
    aws kms schedule-key-deletion --key-id $kms_key --pending-window-in-days 7
}
