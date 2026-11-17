# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

if {![package vsatisfies [package provide Tcl] 9.1-10]} {return}

package ifneeded tconfig::encrypt 1.0.2 [list source [file join $dir tcl encrypt.tcl]]
package ifneeded tconfig::decrypt 1.0.2 [list source [file join $dir tcl decrypt.tcl]]
