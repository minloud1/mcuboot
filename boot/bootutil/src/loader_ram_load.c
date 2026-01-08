/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2019-2023 Arm Limited
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
 * @brief RAM_LOAD mode boot loader implementation.
 *
 * This file contains the boot loader implementation for RAM_LOAD mode,
 * where images are copied to RAM before execution. This provides TOCTOU
 * attack protection by authenticating the image after it is copied to
 * trusted RAM.
 */

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "flash_map_backend/flash_map_backend.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_public.h"
#include "bootutil/image.h"
#include "bootutil_priv.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/boot_hooks.h"
#include "bootutil/ramload.h"
#include "loader_priv.h"

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_RAM_LOAD)

BOOT_LOG_MODULE_DECLARE(mcuboot);

/* External declarations from loader_xip_ram_common.c */
extern int boot_get_slot_usage(struct boot_loader_state *state);
extern uint32_t find_slot_with_highest_version(struct boot_loader_state *state);
extern void fill_rsp_xip_ram(struct boot_loader_state *state, struct boot_rsp *rsp);
extern int boot_update_hw_rollback_protection_xip_ram(struct boot_loader_state *state);

#ifdef MCUBOOT_HAVE_LOGGING
extern void print_loaded_images(struct boot_loader_state *state);
#endif

#if (BOOT_IMAGE_NUMBER > 1)
extern int boot_verify_dependencies_xip_ram(struct boot_loader_state *state);
#endif

#if defined(MCUBOOT_RAM_LOAD_REVERT)
extern int boot_select_or_erase(struct boot_loader_state *state);
#endif

/**
 * Tries to load a slot for all the images with validation.
 *
 * For RAM_LOAD mode, images are first loaded to RAM and then authenticated
 * there to prevent TOCTOU attacks during image copy.
 *
 * @param  state        Boot loader status information.
 *
 * @return              FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
static fih_ret
boot_load_and_validate_images_ram(struct boot_loader_state *state)
{
    uint32_t active_slot;
    int rc;
    fih_ret fih_rc;

    /* Go over all the images and try to load one */
    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        /* All slots tried until a valid image found. Breaking from this loop
         * means that a valid image found or already loaded. If no slot is
         * found the function returns with error code. */
        while (true) {
            /* Go over all the slots and try to load one */
            active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;
            if (active_slot != BOOT_SLOT_NONE){
                /* A slot is already active, go to next image. */
                break;
            }

            rc = BOOT_HOOK_FIND_SLOT_CALL(boot_find_next_slot_hook, BOOT_HOOK_REGULAR,
                                          state, BOOT_CURR_IMG(state), &active_slot);
            if (rc == BOOT_HOOK_REGULAR) {
                active_slot = find_slot_with_highest_version(state);
            }

            if (active_slot == BOOT_SLOT_NONE) {
                BOOT_LOG_INF("No slot to load for image %d",
                             BOOT_CURR_IMG(state));
                FIH_RET(FIH_FAILURE);
            }

            /* Save the number of the active slot. */
            state->slot_usage[BOOT_CURR_IMG(state)].active_slot = active_slot;

#if BOOT_IMAGE_NUMBER > 1
            if (state->img_mask[BOOT_CURR_IMG(state)]) {
                continue;
            }
#endif

#if defined(MCUBOOT_RAM_LOAD_REVERT)
            rc = boot_select_or_erase(state);
            if (rc != 0) {
                /* The selected image slot has been erased. */
                state->slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
                state->slot_usage[BOOT_CURR_IMG(state)].active_slot = BOOT_SLOT_NONE;
                continue;
            }
#endif /* MCUBOOT_RAM_LOAD_REVERT */

            /* RAM_LOAD: Image is first loaded to RAM and authenticated there
             * in order to prevent TOCTOU attack during image copy. This is
             * applied when loading images from external (untrusted) flash to
             * internal (trusted) RAM.
             */
            rc = boot_load_image_to_sram(state);
            if (rc != 0) {
                /* Image cannot be loaded to RAM. */
                boot_remove_image_from_flash(state, active_slot);
                state->slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
                state->slot_usage[BOOT_CURR_IMG(state)].active_slot = BOOT_SLOT_NONE;
                continue;
            }

            FIH_CALL(boot_validate_slot, fih_rc, state, active_slot, NULL, 0);
            if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
                /* Image is invalid. Remove from SRAM. */
                boot_remove_image_from_sram(state);
                state->slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
                state->slot_usage[BOOT_CURR_IMG(state)].active_slot = BOOT_SLOT_NONE;
                continue;
            }

            /* Valid image loaded from a slot, go to next image. */
            break;
        }
    }

    FIH_RET(FIH_SUCCESS);
}

/**
 * Main entry point for RAM_LOAD mode boot process.
 *
 * @param state Boot loader state.
 * @param rsp   Boot response structure to fill with boot information.
 *
 * @return FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_ret
context_boot_go_ram_load(struct boot_loader_state *state, struct boot_rsp *rsp)
{
    int rc;
    FIH_DECLARE(fih_rc, FIH_FAILURE);

    rc = boot_open_all_flash_areas(state);
    if (rc != 0) {
        goto out;
    }

    rc = boot_get_slot_usage(state);
    if (rc != 0) {
        goto close;
    }

#if (BOOT_IMAGE_NUMBER > 1)
    while (true) {
#endif
        FIH_CALL(boot_load_and_validate_images_ram, fih_rc, state);
        if (FIH_NOT_EQ(fih_rc, FIH_SUCCESS)) {
            FIH_SET(fih_rc, FIH_FAILURE);
            goto close;
        }

#if (BOOT_IMAGE_NUMBER > 1)
        rc = boot_verify_dependencies_xip_ram(state);
        if (rc != 0) {
            /* Dependency check failed for an image, it has been removed from
             * SRAM and set to unavailable. Try to load an image from another
             * slot.
             */
            continue;
        }
        /* Dependency check was successful. */
        break;
    }
#endif

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if BOOT_IMAGE_NUMBER > 1
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
#endif
        rc = boot_update_hw_rollback_protection_xip_ram(state);
        if (rc != 0) {
            FIH_SET(fih_rc, FIH_FAILURE);
            goto close;
        }

        rc = boot_add_shared_data(state, (uint8_t)state->slot_usage[BOOT_CURR_IMG(state)].active_slot);
        if (rc != 0) {
            FIH_SET(fih_rc, FIH_FAILURE);
            goto close;
        }
    }

    /* All images loaded successfully. */
#ifdef MCUBOOT_HAVE_LOGGING
    print_loaded_images(state);
#endif

    fill_rsp_xip_ram(state, rsp);

close:
    boot_close_all_flash_areas(state);

out:
    if (rc != 0) {
        FIH_SET(fih_rc, FIH_FAILURE);
    }

    FIH_RET(fih_rc);
}

#endif /* MCUBOOT_RAM_LOAD */
