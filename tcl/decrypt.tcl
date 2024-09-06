# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require tink
package require awskms

source [file join [file dirname [info script]] common.tcl]

namespace eval ::tconfig {}

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

proc ::tconfig::load_config { ini_file { aws_profile {} } } {

    if { $aws_profile eq "" && [info exists ::env(AWS_PROFILE)] } {
        set aws_profile $::env(AWS_PROFILE)
    }

    set config [::tconfig::read_config $ini_file]

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

package provide tconfig::decrypt 1.0.0
