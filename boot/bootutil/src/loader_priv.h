/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2024-2025 Nordic Semiconductor ASA
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * @file
 * @brief Internal declarations for mode-specific boot loader implementations.
 *
 * This header provides declarations for the mode-specific entry point functions
 * used by the boot loader. Each boot mode (SWAP, DIRECT_XIP, RAM_LOAD) has its
 * own implementation file that provides the corresponding context_boot_go_*()
 * function.
 */

#ifndef H_LOADER_PRIV_
#define H_LOADER_PRIV_

#include "bootutil/fault_injection_hardening.h"
#include "bootutil_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

struct boot_loader_state;
struct boot_rsp;
struct boot_status;

/*
 * Mode-specific entry points.
 * Each boot mode provides its own implementation of context_boot_go.
 */

#if !defined(MCUBOOT_DIRECT_XIP) && !defined(MCUBOOT_RAM_LOAD)
/**
 * Main entry point for SWAP mode boot process.
 *
 * Handles image swapping (test/permanent/revert) between primary and secondary
 * slots using the configured swap algorithm (scratch/move/offset).
 *
 * @param state Boot loader state.
 * @param rsp   Boot response structure to fill with boot information.
 *
 * @return FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_ret context_boot_go_swap(struct boot_loader_state *state, struct boot_rsp *rsp);
#endif

#if defined(MCUBOOT_DIRECT_XIP)
/**
 * Main entry point for DIRECT_XIP mode boot process.
 *
 * Selects the best available image slot and executes directly from that slot.
 * No image copying is performed.
 *
 * @param state Boot loader state.
 * @param rsp   Boot response structure to fill with boot information.
 *
 * @return FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_ret context_boot_go_direct_xip(struct boot_loader_state *state, struct boot_rsp *rsp);
#endif

#if defined(MCUBOOT_RAM_LOAD)
/**
 * Main entry point for RAM_LOAD mode boot process.
 *
 * Loads the best available image from flash to RAM before execution.
 * Provides TOCTOU attack protection by authenticating the image after copy.
 *
 * @param state Boot loader state.
 * @param rsp   Boot response structure to fill with boot information.
 *
 * @return FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_ret context_boot_go_ram_load(struct boot_loader_state *state, struct boot_rsp *rsp);
#endif

/*
 * Shared functions accessible to mode-specific implementations.
 * These are defined in loader.c but may be needed by XIP/RAM_LOAD modes.
 */

/**
 * Reads image headers from the flash areas.
 *
 * @param state       Boot loader state.
 * @param require_all If true, all image headers must be valid.
 * @param bs          Boot status (optional, for reading during swap).
 *
 * @return 0 on success; nonzero on failure.
 */
int boot_read_image_headers(struct boot_loader_state *state, bool require_all,
                            struct boot_status *bs);

/**
 * Validates an image in the specified slot.
 *
 * @param state              Boot loader state.
 * @param slot               Slot to validate (BOOT_SLOT_PRIMARY or BOOT_SLOT_SECONDARY).
 * @param bs                 Boot status (optional).
 * @param expected_swap_type Expected swap type for validation context.
 *
 * @return FIH_SUCCESS if image is valid; other FIH value on failure.
 */
fih_ret boot_validate_slot(struct boot_loader_state *state, int slot,
                           struct boot_status *bs, int expected_swap_type);

/**
 * Compares two image versions.
 *
 * @param ver1 First version to compare.
 * @param ver2 Second version to compare.
 *
 * @return -1 if ver1 < ver2, 0 if ver1 == ver2, 1 if ver1 > ver2.
 */
int boot_compare_version(const struct image_version *ver1,
                         const struct image_version *ver2);

/**
 * Checks if an image header appears to have valid magic.
 *
 * @param state Boot loader state.
 * @param slot  Slot to check.
 *
 * @return true if header appears valid; false otherwise.
 */
bool boot_check_header_valid(struct boot_loader_state *state, int slot);

/**
 * Adds shared boot data for the specified slot.
 *
 * @param state Boot loader state.
 * @param slot  Active slot.
 *
 * @return 0 on success; nonzero on failure.
 */
int boot_add_shared_data(struct boot_loader_state *state, uint8_t slot);

/**
 * Updates the security counter for rollback protection.
 *
 * @param state        Boot loader state.
 * @param slot_to_read Slot to read the security counter from.
 * @param slot_to_write Slot to write the security counter to.
 *
 * @return 0 on success; nonzero on failure.
 */
int boot_update_security_counter(struct boot_loader_state *state,
                                 uint32_t slot_to_read, uint32_t slot_to_write);

#ifdef MCUBOOT_HW_ROLLBACK_PROT_LOCK
/**
 * Locks the security counter after update.
 *
 * @param image_index Image index.
 *
 * @return 0 on success; nonzero on failure.
 */
int boot_nv_security_counter_lock(uint8_t image_index);
#endif

/**
 * Scrambles (erases/corrupts) a region of flash.
 *
 * @param fap      Flash area to scramble.
 * @param off      Offset within the flash area.
 * @param size     Size of the region to scramble.
 * @param preserve If true, preserve certain data.
 *
 * @return 0 on success; nonzero on failure.
 */
int boot_scramble_region(const struct flash_area *fap, uint32_t off,
                         uint32_t size, bool preserve);

#ifdef __cplusplus
}
#endif

#endif /* H_LOADER_PRIV_ */
