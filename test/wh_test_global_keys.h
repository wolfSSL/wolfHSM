/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef WH_TEST_GLOBAL_KEYS_H_
#define WH_TEST_GLOBAL_KEYS_H_

/**
 * @brief Test global keys functionality with multiple clients
 *
 * This test suite validates the global keys feature by setting up two
 * independent clients that share a common NVM context. Tests include:
 * - Basic global key operations (cache, export across clients)
 * - Local key isolation (same ID, different clients)
 * - Mixed global and local keys
 * - NVM persistence of global keys
 * - Export protection enforcement
 * - Cache isolation (no cross-cache interference)
 *
 * @return 0 on success, error code on failure
 */
int whTest_GlobalKeys(void);

#endif /* WH_TEST_GLOBAL_KEYS_H_ */
