# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require tink
package require awskms

namespace eval ::tconfig {

    variable config [dict create]

}

proc ::tconfig::get_aws_kms_client { aws_profile } {

    set conf [dict create]

    if { $aws_profile ne "" } {
        if { [info exists ::env(AWS_PROFILE)] } {
            set save_profile $::env(AWS_PROFILE)
        }
        set ::env(AWS_PROFILE) $aws_profile
    }

    if { [info exists ::env(AWS_ENDPOINT_URL)] } {
        dict set conf endpoint $::env(AWS_ENDPOINT_URL)
    }

    set rc [::aws::kms::create $conf]

    if { $aws_profile ne "" } {
        if { [info exists save_profile] } {
            set ::env(AWS_PROFILE) $save_profile
        } else {
            unset ::env(AWS_PROFILE)
        }
    }

    return $rc

}

proc ::tconfig::get_aws_ssm_client { aws_profile } {

    set conf [dict create]

    if { $aws_profile ne "" } {
        if { [info exists ::env(AWS_PROFILE)] } {
            set save_profile $::env(AWS_PROFILE)
        }
        set ::env(AWS_PROFILE) $aws_profile
    }

    if { [info exists ::env(AWS_ENDPOINT_URL)] } {
        dict set conf endpoint $::env(AWS_ENDPOINT_URL)
    }

    set rc [::aws::ssm::create $conf]

    if { $aws_profile ne "" } {
        if { [info exists save_profile] } {
            set ::env(AWS_PROFILE) $save_profile
        } else {
            unset ::env(AWS_PROFILE)
        }
    }

    return $rc

}

proc ::tconfig::get { } {
    variable config
    return $config
}

proc ::tconfig::convert_ini2dict { ini_file } {

    set result [dict create]

    set fd [open $ini_file r]
    while { [gets $fd line] != -1 } {

        set line [string trim $line]

        # skip empty lines and comments
        if { ![string length $line] || [string index $line 0] eq "#" } {
            continue
        }

        # if we found a section name
        if { [string index $line 0] eq "\[" && [string index $line end] eq "\]" } {
            set section [string trim [string range $line 1 end-1]]
            continue
        }

        # Ignore lines if we don't already have a section name
        if { ![info exists section] } {
            continue
        }

        set line [split $line "="]

        # skip lines that do not have the key=value format
        if { [llength $line] <= 1 } {
            continue
        }

        set key [string trim [lindex $line 0]]
        set val [string trim [join [lrange $line 1 end] "="]]
        dict set result $section $key $val

    }
    close $fd

    return $result

}

proc ::tconfig::convert_dict2ini { config_dict ini_file } {

    set fd [open $ini_file w]

    dict for { section keys } $config_dict {
        puts $fd "\[$section\]"
        dict for { key val } $keys {
            puts $fd "$key = $val"
        }
    }

    close $fd

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

proc ::tconfig::decrypt_dict { config_dict tink_keyset } {

    dict for { section keys } $config_dict {
        dict for { key val } $keys {

            # Skip unencrypted key-value pairs
            if { ![string match "enc:*" $key] } {
                continue
            }

            # Remove the encrypted key-value pair from the result
            dict unset config_dict $section $key

            set key [string range $key 4 end]
            set val [binary decode base64 $val]
            set val [::tink::aead::decrypt $tink_keyset $val]

            dict set config_dict $section $key $val

        }
    }

    return $config_dict

}

proc ::tconfig::encrypt_config { option_dict } {

    package require awsssm

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

    set config_dict [convert_ini2dict [dict get $option_dict "config_file"]]

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

    ::tconfig::convert_dict2ini $config_dict [dict get $option_dict "config_file"]

}

proc ::tconfig::load_config { ini_file { aws_profile {} } } {

    variable config

    if { $aws_profile eq "" && [info exists ::env(AWS_PROFILE)] } {
        set aws_profile $::env(AWS_PROFILE)
    }

    set config [convert_ini2dict $ini_file]

    set kms_client [get_aws_kms_client $aws_profile]

    set tink_keyset [dict get $config "tconfig" "tink_keyset"]
    dict unset config tconfig
    set tink_keyset [binary decode base64 $tink_keyset]

    set tink_keyset [$kms_client decrypt $tink_keyset]

    $kms_client destroy

    set tink_keyset [::tink::register_keyset $tink_keyset]

    set config [decrypt_dict $config $tink_keyset]

    ::tink::unregister_keyset $tink_keyset

    return $config

}

package provide tconfig 1.0.0
