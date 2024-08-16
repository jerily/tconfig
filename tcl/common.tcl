# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

namespace eval ::tconfig {}

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

proc ::tconfig::read_config { ini_file } {

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

proc ::tconfig::write_config { config_dict ini_file } {

    set fd [open $ini_file w]

    dict for { section keys } $config_dict {
        puts $fd "\[$section\]"
        dict for { key val } $keys {
            puts $fd "$key = $val"
        }
    }

    close $fd

}
