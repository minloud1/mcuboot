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
 * @brief Shared boot loader code for DIRECT_XIP and RAM_LOAD modes.
 *
 * This file contains functions that are common to both DIRECT_XIP and RAM_LOAD
 * boot modes, including slot usage management, version comparison for slot
 * selection, and dependency verification.
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
#include "loader_priv.h"

#if defined(MCUBOOT_RAM_LOAD)
#include "bootutil/ramload.h"
#endif

#include "mcuboot_config/mcuboot_config.h"

#if defined(MCUBOOT_DIRECT_XIP) || defined(MCUBOOT_RAM_LOAD)

BOOT_LOG_MODULE_DECLARE(mcuboot);

/**
 * Opens all flash areas and checks which contain an image with a valid header.
 *
 * @param  state        Boot loader status information.
 *
 * @return              0 on success; nonzero on failure.
 */
int
boot_get_slot_usage(struct boot_loader_state *state)
{
    uint32_t slot;
    int rc;
    struct image_header *hdr = NULL;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if BOOT_IMAGE_NUMBER > 1
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
#endif
        /* Attempt to read an image header from each slot. */
        rc = boot_read_image_headers(state, false, NULL);
        if (rc != 0) {
            BOOT_LOG_WRN("Failed reading image headers.");
            return rc;
        }

        /* Check headers in all slots */
        for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
            hdr = boot_img_hdr(state, slot);

            if (boot_check_header_valid(state, slot)) {
                state->slot_usage[BOOT_CURR_IMG(state)].slot_available[slot] = true;
                BOOT_LOG_IMAGE_INFO(slot, hdr);
            } else {
                state->slot_usage[BOOT_CURR_IMG(state)].slot_available[slot] = false;
                BOOT_LOG_INF("Image %d %s slot: Image not found",
                             BOOT_CURR_IMG(state),
                             (slot == BOOT_SLOT_PRIMARY)
                             ? "Primary" : "Secondary");
            }
        }

        state->slot_usage[BOOT_CURR_IMG(state)].active_slot = BOOT_SLOT_NONE;
    }

    return 0;
}

/**
 * Finds the slot containing the image with the highest version number for the
 * current image.
 *
 * @param  state        Boot loader status information.
 *
 * @return              BOOT_SLOT_NONE if no available slot found, number of
 *                      the found slot otherwise.
 */
uint32_t
find_slot_with_highest_version(struct boot_loader_state *state)
{
    uint32_t slot;
    uint32_t candidate_slot = BOOT_SLOT_NONE;
    int rc;

    for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
        if (state->slot_usage[BOOT_CURR_IMG(state)].slot_available[slot]) {
            if (candidate_slot == BOOT_SLOT_NONE) {
                candidate_slot = slot;
            } else {
                rc = boot_compare_version(
                            &boot_img_hdr(state, slot)->ih_ver,
                            &boot_img_hdr(state, candidate_slot)->ih_ver);
                if (rc == 1) {
                    /* The version of the image being examined is greater than
                     * the version of the current candidate.
                     */
                    candidate_slot = slot;
                }
            }
        }
    }

    return candidate_slot;
}

#ifdef MCUBOOT_HAVE_LOGGING
/**
 * Prints the state of the loaded images.
 *
 * @param  state        Boot loader status information.
 */
void
print_loaded_images(struct boot_loader_state *state)
{
    uint32_t active_slot;

    (void)state;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if BOOT_IMAGE_NUMBER > 1
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
#endif
        active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;

        BOOT_LOG_INF("Image %d loaded from the %s slot",
                     BOOT_CURR_IMG(state),
                     (active_slot == BOOT_SLOT_PRIMARY) ?
                     "primary" : "secondary");
    }
}
#endif /* MCUBOOT_HAVE_LOGGING */

#if (defined(MCUBOOT_DIRECT_XIP) && defined(MCUBOOT_DIRECT_XIP_REVERT)) || \
    (defined(MCUBOOT_RAM_LOAD) && defined(MCUBOOT_RAM_LOAD_REVERT))
/**
 * Checks whether the active slot of the current image was previously selected
 * to run. Erases the image if it was selected but its execution failed,
 * otherwise marks it as selected if it has not been before.
 *
 * @param  state        Boot loader status information.
 *
 * @return              0 on success; nonzero on failure.
 */
int
boot_select_or_erase(struct boot_loader_state *state)
{
    const struct flash_area *fap = NULL;
    int rc;
    uint32_t active_slot;
    struct boot_swap_state* active_swap_state;

    active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;

    fap = BOOT_IMG_AREA(state, active_slot);
    assert(fap != NULL);

    active_swap_state = &(state->slot_usage[BOOT_CURR_IMG(state)].swap_state);

    memset(active_swap_state, 0, sizeof(struct boot_swap_state));
    rc = boot_read_swap_state(fap, active_swap_state);
    assert(rc == 0);

    if (active_swap_state->magic != BOOT_MAGIC_GOOD ||
        (active_swap_state->copy_done == BOOT_FLAG_SET &&
         active_swap_state->image_ok  != BOOT_FLAG_SET)) {
        /*
         * A reboot happened without the image being confirmed at
         * runtime or its trailer is corrupted/invalid. Erase the image
         * to prevent it from being selected again on the next reboot.
         */
        BOOT_LOG_DBG("Erasing faulty image in the %s slot.",
                     (active_slot == BOOT_SLOT_PRIMARY) ? "primary" : "secondary");
        rc = boot_scramble_region(fap, 0, flash_area_get_size(fap), false);
        assert(rc == 0);
        rc = -1;
    } else {
        if (active_swap_state->copy_done != BOOT_FLAG_SET) {
            if (active_swap_state->copy_done == BOOT_FLAG_BAD) {
                BOOT_LOG_DBG("The copy_done flag had an unexpected value. Its "
                             "value was neither 'set' nor 'unset', but 'bad'.");
            }
            /*
             * Set the copy_done flag, indicating that the image has been
             * selected to boot. It can be set in advance, before even
             * validating the image, because in case the validation fails, the
             * entire image slot will be erased (including the trailer).
             */
            rc = boot_write_copy_done(fap);
            if (rc != 0) {
                BOOT_LOG_WRN("Failed to set copy_done flag of the image in "
                             "the %s slot.", (active_slot == BOOT_SLOT_PRIMARY) ?
                             "primary" : "secondary");
                rc = 0;
            }
        }
    }

    return rc;
}
#endif /* (MCUBOOT_DIRECT_XIP && MCUBOOT_DIRECT_XIP_REVERT) || (MCUBOOT_RAM_LOAD && MCUBOOT_RAM_LOAD_REVERT) */

/**
 * Fills rsp to indicate how booting should occur for XIP/RAM_LOAD modes.
 *
 * @param  state        Boot loader status information.
 * @param  rsp          boot_rsp struct to fill.
 */
void
fill_rsp_xip_ram(struct boot_loader_state *state, struct boot_rsp *rsp)
{
    uint32_t active_slot;

#if (BOOT_IMAGE_NUMBER > 1)
    /* Always boot from the first enabled image. */
    BOOT_CURR_IMG(state) = 0;
    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        if (!state->img_mask[BOOT_CURR_IMG(state)]) {
            break;
        }
    }
    /* At least one image must be active, otherwise skip the execution */
    if (BOOT_CURR_IMG(state) >= BOOT_IMAGE_NUMBER) {
        return;
    }
#endif

    active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;

    rsp->br_flash_dev_id = flash_area_get_device_id(BOOT_IMG_AREA(state, active_slot));
    rsp->br_image_off = boot_img_slot_off(state, active_slot);
    rsp->br_hdr = boot_img_hdr(state, active_slot);
}

#if (BOOT_IMAGE_NUMBER > 1)
/**
 * Verify the image dependency for a single dependency.
 *
 * @param  state        Boot loader status information.
 * @param  dep          Image dependency to verify.
 *
 * @return              0 if dependency is satisfied; nonzero otherwise.
 */
static int
boot_verify_slot_dependency_xip_ram(struct boot_loader_state *state,
                                    struct image_dependency *dep)
{
    struct image_version *dep_version;
    size_t dep_slot;
    int rc;

    /* For XIP/RAM_LOAD modes, use the active slot from slot_usage */
    dep_slot = state->slot_usage[dep->image_id].active_slot;

    dep_version = &state->imgs[dep->image_id][dep_slot].hdr.ih_ver;

    rc = boot_compare_version(dep_version, &dep->image_min_version);
    if (rc >= 0) {
        /* Dependency satisfied. */
        rc = 0;
    }

    return rc;
}

/**
 * Read all dependency TLVs of an image from the flash and verify
 * one after another to see if they are all satisfied.
 *
 * @param state             Boot loader state.
 * @param slot              Image slot number.
 *
 * @return                  0 on success; nonzero on failure.
 */
static int
boot_verify_slot_dependencies_xip_ram(struct boot_loader_state *state, uint32_t slot)
{
    const struct flash_area *fap;
    struct image_tlv_iter it;
    struct image_dependency dep;
    uint32_t off;
    uint16_t len;
    int rc;

    fap = BOOT_IMG_AREA(state, slot);
    assert(fap != NULL);

    BOOT_LOG_DBG("boot_verify_slot_dependencies_xip_ram");

    rc = bootutil_tlv_iter_begin(&it, boot_img_hdr(state, slot), fap,
            IMAGE_TLV_DEPENDENCY, true);
    if (rc != 0) {
        goto done;
    }

    while (true) {
        rc = bootutil_tlv_iter_next(&it, &off, &len, NULL);
        if (rc < 0) {
            return -1;
        } else if (rc > 0) {
            rc = 0;
            break;
        }

        if (len != sizeof(dep)) {
            rc = BOOT_EBADIMAGE;
            goto done;
        }

        rc = LOAD_IMAGE_DATA(boot_img_hdr(state, slot),
                             fap, off, &dep, len);
        if (rc != 0) {
            BOOT_LOG_DBG("boot_verify_slot_dependencies_xip_ram: error %d reading dependency",
                         rc);
            rc = BOOT_EFLASH;
            goto done;
        }

        if (dep.image_id >= BOOT_IMAGE_NUMBER) {
            rc = BOOT_EBADARGS;
            goto done;
        }

        /* Verify dependency. */
        rc = boot_verify_slot_dependency_xip_ram(state, &dep);
        if (rc != 0) {
            BOOT_LOG_DBG("boot_verify_slot_dependencies_xip_ram: not satisfied");
            /* Dependency not satisfied */
            goto done;
        }
    }

done:
    return rc;
}

/**
 * Checks the dependency of all the active slots. If an image found with
 * invalid or not satisfied dependencies the image is removed from SRAM (in
 * case of MCUBOOT_RAM_LOAD strategy) and its slot is set to unavailable.
 *
 * @param  state        Boot loader status information.
 *
 * @return              0 if dependencies are met; nonzero otherwise.
 */
int
boot_verify_dependencies_xip_ram(struct boot_loader_state *state)
{
    int rc = -1;
    uint32_t active_slot;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        if (state->img_mask[BOOT_CURR_IMG(state)]) {
            continue;
        }
        active_slot = state->slot_usage[BOOT_CURR_IMG(state)].active_slot;
        rc = boot_verify_slot_dependencies_xip_ram(state, active_slot);
        if (rc != 0) {
            /* Dependencies not met or invalid dependencies. */

#ifdef MCUBOOT_RAM_LOAD
            boot_remove_image_from_sram(state);
#endif /* MCUBOOT_RAM_LOAD */

            state->slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
            state->slot_usage[BOOT_CURR_IMG(state)].active_slot = BOOT_SLOT_NONE;

            return rc;
        }
    }

    return rc;
}
#endif /* (BOOT_IMAGE_NUMBER > 1) */

/**
 * Updates the security counter for the current image.
 *
 * @param  state        Boot loader status information.
 *
 * @return              0 on success; nonzero on failure.
 */
int
boot_update_hw_rollback_protection_xip_ram(struct boot_loader_state *state)
{
#ifdef MCUBOOT_HW_ROLLBACK_PROT
    int rc;

    /* Update the stored security counter with the newer (active) image's
     * security counter value.
     */
#if defined(MCUBOOT_DIRECT_XIP) && defined(MCUBOOT_DIRECT_XIP_REVERT)
    /* When the 'revert' mechanism is enabled in direct-xip mode, the
     * security counter can be increased only after reboot, if the image
     * has been confirmed at runtime (the image_ok flag has been set).
     * This way a 'revert' can be performed when it's necessary.
     */
    if (state->slot_usage[BOOT_CURR_IMG(state)].swap_state.image_ok == BOOT_FLAG_SET) {
#endif
        rc = boot_update_security_counter(state,
                                          state->slot_usage[BOOT_CURR_IMG(state)].active_slot,
                                          state->slot_usage[BOOT_CURR_IMG(state)].active_slot);
        if (rc != 0) {
            BOOT_LOG_ERR("Security counter update failed after image %d validation.",
                         BOOT_CURR_IMG(state));
            return rc;
        }

#ifdef MCUBOOT_HW_ROLLBACK_PROT_LOCK
        rc = boot_nv_security_counter_lock(BOOT_CURR_IMG(state));
        if (rc != 0) {
            BOOT_LOG_ERR("Security counter lock failed after image %d validation.",
                         BOOT_CURR_IMG(state));
            return rc;
        }
#endif /* MCUBOOT_HW_ROLLBACK_PROT_LOCK */
#if defined(MCUBOOT_DIRECT_XIP) && defined(MCUBOOT_DIRECT_XIP_REVERT)
    }
#endif

    return 0;

#else /* MCUBOOT_HW_ROLLBACK_PROT */
    (void) (state);
    return 0;
#endif
}

#endif /* MCUBOOT_DIRECT_XIP || MCUBOOT_RAM_LOAD */
