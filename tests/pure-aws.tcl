# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

package require Tcl 9.1
package require tcltest 2
namespace import ::tcltest::*
lappend auto_path [file dirname [file dirname [file normalize [info script]]]]
package require tconfig::encrypt 1.0.2
package require tconfig::decrypt 1.0.2

test pure-ssm {real SSM client preserves profile settings and encrypts parameter values} -setup {
    set savedProfile [array get ::env AWS_PROFILE]
    set savedEndpoint [array get ::env AWS_ENDPOINT_URL]
    set ::env(AWS_PROFILE) previous
    set ::env(AWS_ENDPOINT_URL) http://127.0.0.1:1
    set client [::tconfig::get_aws_ssm_client fixture]
    oo::objdefine $client method awsrequest {method url headers body retry} {
        set request [::aws::core::json_decode $body]
        if {![dict get $request WithDecryption]} {error "SSM decryption was not requested"}
        if {[dict get $headers X-Amz-Target] ne "AmazonSSM.GetParameter"} {error "unexpected SSM operation"}
        set parameter [dict create Name [list S [dict get $request Name]] Type {S SecureString} \
            Value {S secret} Version {N 1}]
        return [dict create body [encoding convertto utf-8 [::aws::core::json_encode \
            [dict create Parameter [list M $parameter]]]]]
    }
    set keyset [::tink::register_keyset [::tink::aead::create_keyset AES256_GCM]]
} -body {
    set encrypted [::tconfig::encrypt_dict {db {password placeholder}} $client $keyset {environment test}]
    list [dict get [$client awsconfig] profile] $::env(AWS_PROFILE) \
        [dict get [$client awsconfig] endpoint] [dict exists $encrypted db enc:password] \
        [::tconfig::decrypt_dict $encrypted $keyset]
} -cleanup {
    $client destroy
    ::tink::unregister_keyset $keyset
    unset ::env(AWS_PROFILE) ::env(AWS_ENDPOINT_URL)
    array set ::env $savedProfile
    array set ::env $savedEndpoint
} -result {fixture previous http://127.0.0.1:1 1 {db {password secret}}}

test pure-kms {load_config unwraps binary KMS output and decrypts the existing file format} -setup {
    set rawKeyset [::tink::aead::create_keyset AES256_GCM]
    set keyset [::tink::register_keyset $rawKeyset]
    set ciphertext [::tink::aead::encrypt $keyset secret]
    ::tink::unregister_keyset $keyset
    set file [makeFile {} config.ini]
    ::tconfig::write_config [dict create tconfig [dict create tink_keyset \
        [binary encode base64 [binary format H* 00ff80]]] db [dict create \
        hostname localhost enc:password [binary encode base64 $ciphertext]]] $file
    set ::kmsClient [::aws::kms::create {region us-east-1 endpoint http://127.0.0.1:1}]
    set ::kmsPlaintext $rawKeyset
    oo::objdefine $::kmsClient method awsrequest {method url headers body retry} {
        set request [::aws::core::json_decode $body]
        if {[dict get $headers X-Amz-Target] ne "TrentService.Decrypt" ||
            [dict get $request CiphertextBlob] ne "AP+A"} {error "unexpected KMS request"}
        return [dict create body [encoding convertto utf-8 [::aws::core::json_encode \
            [dict create Plaintext [list S [binary encode base64 -maxlen 0 $::kmsPlaintext]]]]]]
    }
    rename ::tconfig::get_aws_kms_client ::tconfig::saved_kms_client
    interp alias {} ::tconfig::get_aws_kms_client {} apply {{profile} {return $::kmsClient}}
} -body {
    list [::tconfig::load_config $file fixture] [llength [info commands $::kmsClient]]
} -cleanup {
    catch {$::kmsClient destroy}
    rename ::tconfig::get_aws_kms_client {}
    rename ::tconfig::saved_kms_client ::tconfig::get_aws_kms_client
    unset ::kmsClient ::kmsPlaintext
    removeFile $file
} -result {{db {hostname localhost password secret}} 0}

set failed $::tcltest::numTests(Failed)
cleanupTests
exit [expr {$failed > 0}]
