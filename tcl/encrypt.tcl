# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require tink
package require awskms
package require awsssm

source [file join [file dirname [info script]] common.tcl]

namespace eval ::tconfig {

    variable config [dict create]

}

proc ::tconfig::encrypt_dict { config_dict ssm_client tink_keyset option_dict } {

    set environment [dict get $option_dict "environment"]

    dict for { section keys } $config_dict {
        dict for { key val } $keys {

            if { [dict exists $option_dict "application"] } {
                set smm_param_name "/[dict get $option_dict "application"]/$environment/$section/$key"
            } else {
                set smm_param_name "/$environment/$section/$key"
            }

            # If we cannot get a parameter from SSM, consider it a static
            # parameter that should not be processed.
            if { [catch { $ssm_client get_parameter $smm_param_name true } ssm_value] } {
                continue
            }

            set val [dict get $ssm_value "value"]

            # If value type is not SecureString, then store it in config file in plain text.
            if { [dict get $ssm_value "type"] ne "SecureString" } {
                dict set config_dict $section $key $val
                continue
            }

            # Unset the previous unencrypted value
            dict unset config_dict $section $key

            set key "enc:$key"
            set val [::tink::aead::encrypt $tink_keyset $val]
            set val [binary encode base64 $val]
            dict set config_dict $section $key $val

        }
    }

    return $config_dict

}

proc ::tconfig::encrypt_config { option_dict } {

    if { ![dict exists $option_dict "aws_profile"] } {
        if { [info exists ::env(AWS_PROFILE)] } {
            dict set option_dict "aws_profile" $::env(AWS_PROFILE)
        } else {
            dict set option_dict "aws_profile" ""
        }
    }

    if { ![dict exists $option_dict "config_file"] } {
        return -code error "required option config_file is not specified"
    } elseif { ![dict exists $option_dict "environment"] } {
        return -code error "required option environment is not specified"
    } elseif { ![dict exists $option_dict "aws_kms_key"] } {
        return -code error "required option aws_kms_key is not specified"
    }

    set config_dict [::tconfig::read_config [dict get $option_dict "config_file"]]

    # Generate a new tink key
    set tink_keyset [::tink::aead::create_keyset "AES256_GCM"]

    # Encrypt the key with AWS KMS to exit with an error in case of any
    # communication issue with AWS.
    set kms_client [get_aws_kms_client [dict get $option_dict aws_profile]]
    set tink_keyset_encrypted [$kms_client encrypt [dict get $option_dict aws_kms_key] $tink_keyset]
    # We don't need the KMS client anymore
    $kms_client destroy
    dict set config_dict "tconfig" "tink_keyset" [binary encode base64 $tink_keyset_encrypted]

    set tink_keyset [::tink::register_keyset $tink_keyset]

    set ssm_client [get_aws_ssm_client [dict get $option_dict aws_profile]]

    set config_dict [encrypt_dict $config_dict $ssm_client $tink_keyset $option_dict]

    $ssm_client destroy
    ::tink::unregister_keyset $tink_keyset

    ::tconfig::write_config $config_dict [dict get $option_dict "config_file"]

}

package provide tconfig::encrypt 1.0.0
