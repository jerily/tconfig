# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2024 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.

package ifneeded tconfig::encrypt 1.0.0 [list source [file join $dir tcl encrypt.tcl]]
package ifneeded tconfig::decrypt 1.0.0 [list source [file join $dir tcl decrypt.tcl]]
