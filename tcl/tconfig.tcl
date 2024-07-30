# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package require tink
package require awskms

namespace eval ::tconfig {

    variable config [dict create]

}

proc ::tconfig::get_aws_kms_client { aws_profile } {
    set aws_config [dict create endpoint "http://localhost:4566"]
    return [::aws::kms::create $aws_config]
}

proc ::tconfig::get_aws_ssm_client { aws_profile } {
    set aws_config [dict create endpoint "http://localhost:4566"]
    return [::aws::ssm::create $aws_config]
}

proc ::tconfig::init { args } {

    variable config

    if { [info exists ::env(AWS_PROFILE)] } {
        set aws_profile $::env(AWS_PROFILE)
    } else {
        set aws_profile ""
    }

    if { [llength $args] ni {1 3} } {
        return -code error "wrong # args: should be \"tconfig::init\
            ?-aws_profile profile? path_to_config_file\""
    } else {
        set config_file [lindex $args end]
        if { [llength $args] == 3 } {
            if { [lindex $args 0] != "-aws_profile" } {
                return -code error "unknown option \"[lindex $args 0]\" where\
                    -aws_profile is expected"
            }
            set aws_profile [lindex $args 1]
        }
    }

    set config [dict create]
    set config_encrypted [dict create]

    if { [catch {

        set section ""
        set fd [open $config_file r]
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

            # if we are here, then we expect a key=value pair

            set split [split $line "="]
            set key [string trim [lindex $split 0]]
            set val [string trim [join [lrange $split 1 end] "="]]

            set split [split $key ":"]

            # the case - key=val
            if { [llength $split] == 1 } {
                dict set config $section $key $val
                continue
            }

            set prefix [lindex $split 0]
            set key [string trim [join [lrange $split 1 end] ":"]]

            # the case - plain:key=val
            if { $prefix ne "encrypt" } {
                dict set config $section $key $val
                continue
            }

            # the case - encrypt:key=val
            dict set config_encrypted $section $key $val

        }
        close $fd

    } err] } {
        return -code error "Error while reading configuration file \"$config_file\": $err"
    }

    # If there are no encrypted keys, then just return
    if { ![dict size $config_encrypted] } {
        if { [dict exists $config tconfig] } {
            dict unset config tconfig
        }
        return
    }

    # Check if we have tink keyset
    if { ![dict exists $config "tconfig" "tink_keyset"] } {
        set config [dict create]
        return -code error "Encryption key not found in config file"
    }

    set kms_client [get_aws_kms_client $aws_profile]

    set tink_keyset [dict get $config "tconfig" "tink_keyset"]
    dict unset config tconfig
    set tink_keyset [binary decode base64 $tink_keyset]

    set tink_keyset [$kms_client decrypt $tink_keyset]

    $kms_client destroy

    set tink_keyset [::tink::register_keyset $tink_keyset]

    dict for { section keys } $config_encrypted {
        dict for { key val } $keys {
            set val [binary decode base64 $val]
            dict set config $section $key [::tink::aead::decrypt $tink_keyset $val]
        }
    }

    ::tink::unregister_keyset $tink_keyset

}

proc ::tconfig::get { section key } {
    variable config
    if { ![dict exists $config $section] } {
        if { [dict size $config] } {
            return -code error "Unknown section \"$section\". There are sections:\
                \"[join [dict keys $config] {", "}]\""
        } else {
            return -code error "Unknown section \"$section\".\
                Configuration is not initialized."
        }
    }
    if { ![dict exists $config $section $key] } {
        return -code error "Unknown key \"$key\" in section \"$section\".\
            There are keys:\
            \"[join [dict keys [dict get $config $section]] {", "}]\""
    }
    return [dict get $config $section $key]
}

proc ::tconfig::sections { } {
    variable config
    return [dict keys $config]
}

proc ::tconfig::keys { section } {
    variable config
    if { ![dict exists $config $section] } {
        if { [dict size $config] } {
            return -code error "Unknown section \"$section\". There are sections:\
                \"[join [dict keys $config] {", "}]\""
        } else {
            return -code error "Unknown section \"$section\".\
                Configuration is not initialized."
        }
    }
    return [dict keys [dict get $config $section]]
}

proc ::tconfig::deploy { args } {

    package require awsssm

    if { ![llength $args] } {
        set args $::argv
    }

    array set params [list]

    if { [info exists ::env(AWS_PROFILE)] } {
        set params(aws_profile) $::env(AWS_PROFILE)
    } else {
        set params(aws_profile) ""
    }

    # Parse/validate parameters
    for { set i 0 } { $i < [llength $args] } { incr i } {
        switch -glob -- [lindex $args $i] {
            -env* {
                set var "environment"
            }
            -aws_profile {
                set var "aws_profile"
            }
            -aws_kms_key {
                set var "aws_kms_key"
            }
            -app* {
                set var "app_id"
            }
            -* {
                return -code error "Unknown option \"[lindex $args $i]\".\
                    Supported options are -environment, -aws_kms_key,\
                    -aws_profile or -application"
            }
            * {
                # If this argument is the last one, then it is the filename
                # of the configuration file.
                if { ($i + 1) != [llength $args] } {
                    return -code error "wrong # args: should be \"tconfig::deploy\
                        ?-app application_id? ?-aws_profile profile? -aws_kms_key key_id\
                        -environment environment path_to_config_file\""
                }
                set params(config_file) [lindex $args $i]
                break
            }
        }
        set params($var) [lindex $args [incr i]]
    }

    if { ![info exists params(config_file)] } {
        return -code error "required parameter path_to_config_file is not specified.\
            should be \"tconfig::deploy ?-app application_id? ?-aws_profile profile?\
            -aws_kms_key key_id -environment environment path_to_config_file\""
    } elseif { ![info exists params(environment)] } {
        return -code error "required option -environment is not specified.\
            should be \"tconfig::deploy ?-app application_id? ?-aws_profile profile?\
            -aws_kms_key key_id -environment environment path_to_config_file\""
    } elseif { ![info exists params(aws_kms_key)] } {
        return -code error "required option -aws_kms_key is not specified.\
            should be \"tconfig::deploy ?-app application_id? ?-aws_profile profile?\
            -aws_kms_key key_id -environment environment path_to_config_file\""
    }

    # The first thing we do is read and validate the given configuration file
    # to exit with an error if something is wrong.

    set conf [dict create]

    if { [catch {
        set count 0
        set section ""
        set fd [open $params(config_file) r]
        while { [gets $fd line] != -1 } {

            incr count
            set line [string trim $line]

            # skip empty lines and comments
            if { ![string length $line] || [string index $line 0] eq "#" } {
                continue
            }

            # if we found a section name
            if { [string index $line 0] eq "\[" && [string index $line end] eq "\]" } {
                # TODO: validate the key name according to the rules?
                # https://docs.aws.amazon.com/cli/latest/reference/ssm/put-parameter.html#options
                set section [string trim [string range $line 1 end-1]]
                continue
            }

            # if we are here, then we expect a key=value pair

            set split [split $line "="]
            if { [llength $split] <= 1 } {
                return -code error "expected a key=value pair on line #$count,\
                    but got \"$line\""
            }

            # verify if we have a section name defined
            if { $section eq "" } {
                return -code error "found a key=value pair \"$line\" on line #$count\
                    without the corresponding section name"
            }

            set key [string trim [lindex $split 0]]
            set val [string trim [join [lrange $split 1 end] "="]]

            # check for key prefix
            set split [split $key ":"]

            # if the key does not have a prefix, leave it as it is
            if { [llength $split] <= 1 } {
                continue
            }

            set prefix [string trim [lindex $split 0]]

            if { $prefix ni {encrypt plain} } {
                return -code error "found unexpected prefix \"$prefix\" for key \"$key\"\
                    in section \"$section\" on line #$count"
            }

            # TODO: validate the key name according to the rules?
            # https://docs.aws.amazon.com/cli/latest/reference/ssm/put-parameter.html#options

            dict set conf $section $key $prefix

        }
        close $fd
    } err] } {
        return -code error "Error while reading configuration file \"$params(config_file)\": $err"
    }

    # Generate a new tink key
    set tink_keyset [::tink::aead::create_keyset "AES256_GCM"]

    # Encrypt the key with AWS KMS to exit with an error in case of any
    # communication issue with AWS.
    set kms_client [get_aws_kms_client $params(aws_profile)]
    set tink_keyset_encrypted [$kms_client encrypt $params(aws_kms_key) $tink_keyset]
    # We don't need the KMS client anymore
    $kms_client destroy
    set tink_keyset_encrypted [binary encode base64 $tink_keyset_encrypted]

    set tink_keyset [::tink::register_keyset $tink_keyset]

    set ssm_client [get_aws_ssm_client $params(aws_profile)]

    # Go through all the values to get them from SSM and encrypt if necessary
    dict for { section keys } $conf {
        dict for { key prefix } $keys {
            # strip a prefix from the key name
            set ssm_key [string trim [join [lrange [split $key ":"] 1 end] ":"]]
            set ssm_key "/$params(environment)/$section/$ssm_key"
            if { [info exists conf(app_id)] } {
                set ssm_key "/$params(app_id)$ssm_key"
            }
            if { [catch { set ssm_value [$ssm_client get_parameter $ssm_key] } err] } {
                $ssm_client destroy
                ::tink::unregister_keyset $tink_keyset
                return -code error "Unable to get parameter from SSM using\
                    the key \"$ssm_key\": $err"
            }
            if { $prefix eq "encrypt" } {
                set ssm_value [::tink::aead::encrypt $tink_keyset $ssm_value]
                set ssm_value [binary encode base64 $ssm_value]
            }
            dict set conf $section $key $ssm_value
        }
    }

    $ssm_client destroy
    ::tink::unregister_keyset $tink_keyset

    # Let's create a temporary file and write the values from SSM there
    # so that we don't corrupt the original configuration file
    # in case of any error.

    set fdo [file tempfile temp_config_file]
    if { [catch {

        puts $fdo {[tconfig]}
        puts $fdo "tink_keyset = $tink_keyset_encrypted"
        puts $fdo ""

        set section ""
        set fdi [open $params(config_file) r]
        while { [gets $fdi line] != -1 } {

            set line [string trim $line]

            # skip empty lines and comments
            if { ![string length $line] || [string index $line 0] eq "#" } {
                puts $fdo $line
                continue
            }

            # if we found a section name
            if { [string index $line 0] eq "\[" && [string index $line end] eq "\]" } {
                set section [string trim [string range $line 1 end-1]]
                puts $fdo $line
                continue
            }

            # if we are here, then we expect a key=value pair

            set split [split $line "="]
            set key [string trim [lindex $split 0]]

            if { [dict exists $conf $section $key] } {
                puts $fdo "$key = [dict get $conf $section $key]"
            } else {
                puts $fdo $line
            }

        }
        close $fdi
        close $fdo
    } err] } {
        catch { close $fdi }
        catch { close $fdo }
        catch { file delete -force -- $temp_config_file }
        return -code error "Error while writing output config file to \"$temp_config_file\": $err"
    }

    file rename -force -- $temp_config_file $params(config_file)

}
