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
 * @brief Public entry point dispatcher for boot loader.
 *
 * This file provides the public context_boot_go() function that dispatches
 * to the appropriate mode-specific implementation based on compile-time
 * configuration.
 */

#include "bootutil/bootutil.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil_priv.h"
#include "loader_priv.h"

#include "mcuboot_config/mcuboot_config.h"

/**
 * Main entry point for the boot process.
 *
 * This function dispatches to the appropriate mode-specific implementation
 * based on compile-time configuration:
 * - MCUBOOT_DIRECT_XIP: Execute directly from flash slot
 * - MCUBOOT_RAM_LOAD: Load to RAM before execution
 * - Default (SWAP modes): Swap images between slots
 *
 * @param state Boot loader state.
 * @param rsp   Boot response structure to fill with boot information.
 *
 * @return FIH_SUCCESS on success; FIH_FAILURE on failure.
 */
fih_ret
context_boot_go(struct boot_loader_state *state, struct boot_rsp *rsp)
{
#if defined(MCUBOOT_DIRECT_XIP)
    return context_boot_go_direct_xip(state, rsp);
#elif defined(MCUBOOT_RAM_LOAD)
    return context_boot_go_ram_load(state, rsp);
#else
    return context_boot_go_swap(state, rsp);
#endif
}
