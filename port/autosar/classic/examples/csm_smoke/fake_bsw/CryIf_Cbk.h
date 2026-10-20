/*
 * Copyright (C) 2026 wolfSSL Inc.
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
/*
 * Minimal CryIf callback header for csm_smoke. A real BSW supplies this.
 */
#ifndef CRYIF_CBK_H_
#define CRYIF_CBK_H_

#include "Std_Types.h"
#include "Crypto_GeneralTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Called by Crypto_MainFunction on async completion. */
void CryIf_CallbackNotification(Crypto_JobType* job, Std_ReturnType result);

#ifdef __cplusplus
}
#endif
#endif /* CRYIF_CBK_H_ */
