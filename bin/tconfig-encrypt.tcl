# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require tconfig::encrypt

proc convert_argv2options { argv } {

    set result [dict create]

    # The last argument is a config file name
    dict set result "config_file" [lindex $argv end]

    # Convert all other parameters from:
    #     -aws_profile XXX -environment YYY
    # to dict:
    #     aws_profile XXX environment YYY
    foreach { name value } [lrange $argv 0 end-1] {
        switch -glob -- $name {
            -env* {
                set name "environment"
            }
            -aws_kms_key {
                set name "aws_kms_key"
            }
            -aws_profile {
                set name "aws_profile"
            }
            -app* {
                set name "application"
            }
            default {
                puts stderr "Error: unknown option \"$name\": should be -environment\
                    -aws_kms_key, -aws_profile or -application"
                exit 1
            }
        }
        dict set result $name $value
    }

    return $result

}

::tconfig::encrypt_config [convert_argv2options $argv]
