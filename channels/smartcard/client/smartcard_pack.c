/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Smart Card Structure Packing
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/crt.h>
#include <winpr/print.h>

#include "smartcard_pack.h"

UINT32 smartcard_unpack_common_type_header(SMARTCARD_DEVICE* smartcard, wStream* s)
{
	UINT8 version;
	UINT32 filler;
	UINT8 endianness;
	UINT16 commonHeaderLength;

	if (Stream_GetRemainingLength(s) < 8)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "CommonTypeHeader is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	/* Process CommonTypeHeader */

	Stream_Read_UINT8(s, version); /* Version (1 byte) */
	Stream_Read_UINT8(s, endianness); /* Endianness (1 byte) */
	Stream_Read_UINT16(s, commonHeaderLength); /* CommonHeaderLength (2 bytes) */
	Stream_Read_UINT32(s, filler); /* Filler (4 bytes), should be 0xCCCCCCCC */

	if (version != 1)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Unsupported CommonTypeHeader Version %d", version);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (endianness != 0x10)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Unsupported CommonTypeHeader Endianness %d", endianness);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (commonHeaderLength != 8)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Unsupported CommonTypeHeader CommonHeaderLength %d", commonHeaderLength);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (filler != 0xCCCCCCCC)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Unexpected CommonTypeHeader Filler 0x%08X", filler);
		return SCARD_F_INTERNAL_ERROR;
	}

	return 0;
}

UINT32 smartcard_pack_common_type_header(SMARTCARD_DEVICE* smartcard, wStream* s)
{
	Stream_Write_UINT8(s, 1); /* Version (1 byte) */
	Stream_Write_UINT8(s, 0x10); /* Endianness (1 byte) */
	Stream_Write_UINT16(s, 8); /* CommonHeaderLength (2 bytes) */
	Stream_Write_UINT32(s, 0xCCCCCCCC); /* Filler (4 bytes), should be 0xCCCCCCCC */

	return 0;
}

UINT32 smartcard_unpack_private_type_header(SMARTCARD_DEVICE* smartcard, wStream* s)
{
	UINT32 filler;
	UINT32 objectBufferLength;

	if (Stream_GetRemainingLength(s) < 8)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "PrivateTypeHeader is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, objectBufferLength); /* ObjectBufferLength (4 bytes) */
	Stream_Read_UINT32(s, filler); /* Filler (4 bytes), should be 0x00000000 */

	if (filler != 0x00000000)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Unexpected PrivateTypeHeader Filler 0x%08X", filler);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (objectBufferLength != Stream_GetRemainingLength(s))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "PrivateTypeHeader ObjectBufferLength mismatch: Actual: %d, Expected: %d",
				(int) objectBufferLength, Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	return 0;
}

UINT32 smartcard_pack_private_type_header(SMARTCARD_DEVICE* smartcard, wStream* s, UINT32 objectBufferLength)
{
	Stream_Write_UINT32(s, objectBufferLength); /* ObjectBufferLength (4 bytes) */
	Stream_Write_UINT32(s, 0x00000000); /* Filler (4 bytes), should be 0x00000000 */

	return 0;
}

UINT32 smartcard_unpack_redir_scard_context(SMARTCARD_DEVICE* smartcard, wStream* s, REDIR_SCARDCONTEXT* context)
{
	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDCONTEXT is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, context->cbContext); /* cbContext (4 bytes) */

	if ((Stream_GetRemainingLength(s) < context->cbContext) || (!context->cbContext))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDCONTEXT is too short: Actual: %d, Expected: %d",
				(int) Stream_GetRemainingLength(s), context->cbContext);
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek_UINT32(s); /* pbContextNdrPtr (4 bytes) */

	if (context->cbContext > Stream_GetRemainingLength(s))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDCONTEXT is too long: Actual: %d, Expected: %d",
				(int) Stream_GetRemainingLength(s), context->cbContext);
		return SCARD_F_INTERNAL_ERROR;
	}

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_redir_scard_context_ref(SMARTCARD_DEVICE* smartcard, wStream* s, REDIR_SCARDCONTEXT* context)
{
	UINT32 length;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDCONTEXT is too short: Actual: %d, Expected: %d\n",
				(int) Stream_GetRemainingLength(s), 4);
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, length); /* Length (4 bytes) */

	if ((length != 4) && (length != 8))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDCONTEXT length is not 4 or 8: %d\n", length);
		return SCARD_F_INTERNAL_ERROR;
	}

	if ((Stream_GetRemainingLength(s) < length) || (!length))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDCONTEXT is too short: Actual: %d, Expected: %d\n",
				(int) Stream_GetRemainingLength(s), length);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (length > 4)
		Stream_Read_UINT64(s, context->pbContext);
	else
		Stream_Read_UINT32(s, context->pbContext);

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_redir_scard_handle(SMARTCARD_DEVICE* smartcard, wStream* s, REDIR_SCARDHANDLE* handle)
{
	UINT32 status;
	UINT32 length;

	status = smartcard_unpack_redir_scard_context(smartcard, s, &(handle->Context));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "SCARDHANDLE is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, length); /* Length (4 bytes) */

	if ((Stream_GetRemainingLength(s) < length) || (!length))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "SCARDHANDLE is too short: Actual: %d, Expected: %d",
				(int) Stream_GetRemainingLength(s), length);
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek_UINT32(s); /* NdrPtr (4 bytes) */

	return 0;
}

UINT32 smartcard_unpack_redir_scard_handle_ref(SMARTCARD_DEVICE* smartcard, wStream* s, REDIR_SCARDHANDLE* handle)
{
	UINT32 length;
	UINT32 status;

	status = smartcard_unpack_redir_scard_context_ref(smartcard, s, &(handle->Context));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDHANDLE is too short: Actual: %d, Expected: %d\n",
				(int) Stream_GetRemainingLength(s), 4);
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, length); /* Length (4 bytes) */

	if ((length != 4) && (length != 8))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDHANDLE length is not 4 or 8: %d\n", length);
		return SCARD_F_INTERNAL_ERROR;
	}

	if ((Stream_GetRemainingLength(s) < length) || (!length))
	{
		WLog_Print(smartcard->log, WLOG_WARN, "REDIR_SCARDHANDLE is too short: Actual: %d, Expected: %d\n",
				(int) Stream_GetRemainingLength(s), length);
		return SCARD_F_INTERNAL_ERROR;
	}

	if (length > 4)
		Stream_Read_UINT64(s, handle->pbHandle);
	else
		Stream_Read_UINT32(s, handle->pbHandle);

	return 0;
}

UINT32 smartcard_unpack_establish_context_call(SMARTCARD_DEVICE* smartcard, wStream* s, EstablishContext_Call* call)
{
	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "EstablishContext_Call is too short: Actual: %d, Expected: %d\n",
				(int) Stream_GetRemainingLength(s), 4);
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->dwScope); /* dwScope (4 bytes) */

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_context_call(SMARTCARD_DEVICE* smartcard, wStream* s, Context_Call* call)
{
	UINT32 status;

	status = smartcard_unpack_redir_scard_context(smartcard, s, &(call->Context));

	if (status)
		return status;

	status = smartcard_unpack_redir_scard_context_ref(smartcard, s, &(call->Context));

	if (status)
		return status;

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_list_readers_call(SMARTCARD_DEVICE* smartcard, wStream* s, ListReaders_Call* call)
{
	UINT32 status;

	status = smartcard_unpack_redir_scard_context(smartcard, s, &(call->Context));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 16)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "ListReaders_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->cBytes); /* cBytes (4 bytes) */

	if (Stream_GetRemainingLength(s) < call->cBytes)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "ListReaders_Call is too short: Actual: %d, Expected: %d",
				(int) Stream_GetRemainingLength(s), call->cBytes);
		return SCARD_F_INTERNAL_ERROR;
	}

	call->mszGroups = NULL;
	Stream_Seek_UINT32(s); /* mszGroupsNdrPtr (4 bytes) */

	Stream_Read_UINT32(s, call->fmszReadersIsNULL); /* fmszReadersIsNULL (4 bytes) */
	Stream_Read_UINT32(s, call->cchReaders); /* cchReaders (4 bytes) */

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "ListReaders_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	status = smartcard_unpack_redir_scard_context_ref(smartcard, s, &(call->Context));

	if (status)
		return status;

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_connect_common(SMARTCARD_DEVICE* smartcard, wStream* s, Connect_Common* common)
{
	UINT32 status;

	if (Stream_GetRemainingLength(s) < 8)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Connect_Common is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	status = smartcard_unpack_redir_scard_context(smartcard, s, &(common->Context));

	if (status)
		return status;

	Stream_Read_UINT32(s, common->dwShareMode); /* dwShareMode (4 bytes) */
	Stream_Read_UINT32(s, common->dwPreferredProtocols); /* dwPreferredProtocols (4 bytes) */

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_read_offset_align(SMARTCARD_DEVICE* smartcard, wStream* s, UINT32 alignment)
{
	UINT32 pad;
	UINT32 offset;

	offset = Stream_GetPosition(s);

	pad = offset;
	offset = (offset + alignment - 1) & ~(alignment - 1);
	pad = offset - pad;

	Stream_Seek(s, pad);

	return pad;
}

UINT32 smartcard_unpack_connect_a_call(SMARTCARD_DEVICE* smartcard, wStream* s, ConnectA_Call* call)
{
	UINT32 status;
	UINT32 count;

	call->szReader = NULL;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "ConnectA_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek_UINT32(s); /* szReaderPointer (4 bytes) */

	status = smartcard_unpack_connect_common(smartcard, s, &(call->Common));

	if (status)
		return status;

	/* szReader */

	Stream_Seek_UINT32(s); /* NdrMaxCount (4 bytes) */
	Stream_Seek_UINT32(s); /* NdrOffset (4 bytes) */
	Stream_Read_UINT32(s, count); /* NdrActualCount (4 bytes) */

	call->szReader = malloc(count + 1);
	Stream_Read(s, call->szReader, count);
	smartcard_unpack_read_offset_align(smartcard, s, 4);
	call->szReader[count] = '\0';

	smartcard_unpack_redir_scard_context_ref(smartcard, s, &(call->Common.Context));

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_connect_w_call(SMARTCARD_DEVICE* smartcard, wStream* s, ConnectW_Call* call)
{
	UINT32 status;
	UINT32 count;

	call->szReader = NULL;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "ConnectA_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek_UINT32(s); /* szReaderPointer (4 bytes) */

	status = smartcard_unpack_connect_common(smartcard, s, &(call->Common));

	if (status)
		return status;

	/* szReader */

	Stream_Seek_UINT32(s); /* NdrMaxCount (4 bytes) */
	Stream_Seek_UINT32(s); /* NdrOffset (4 bytes) */
	Stream_Read_UINT32(s, count); /* NdrActualCount (4 bytes) */

	call->szReader = malloc((count + 1) * 2);
	Stream_Read(s, call->szReader, (count * 2));
	smartcard_unpack_read_offset_align(smartcard, s, 4);
	call->szReader[count] = '\0';

	smartcard_unpack_redir_scard_context_ref(smartcard, s, &(call->Common.Context));

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_reconnect_call(SMARTCARD_DEVICE* smartcard, wStream* s, Reconnect_Call* call)
{
	UINT32 status;

	status = smartcard_unpack_redir_scard_handle(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 12)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Reconnect_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->dwShareMode); /* dwShareMode (4 bytes) */
	Stream_Read_UINT32(s, call->dwPreferredProtocols); /* dwPreferredProtocols (4 bytes) */
	Stream_Read_UINT32(s, call->dwInitialization); /* dwInitialization (4 bytes) */

	status = smartcard_unpack_redir_scard_handle_ref(smartcard, s, &(call->hCard));

	if (status)
		return status;

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_hcard_and_disposition_call(SMARTCARD_DEVICE* smartcard, wStream* s, HCardAndDisposition_Call* call)
{
	UINT32 status;

	status = smartcard_unpack_redir_scard_handle(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "HCardAndDisposition_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->dwDisposition); /* dwDisposition (4 bytes) */

	status = smartcard_unpack_redir_scard_handle_ref(smartcard, s, &(call->hCard));

	if (status)
		return status;

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_get_status_change_a_call(SMARTCARD_DEVICE* smartcard, wStream* s, GetStatusChangeA_Call* call)
{
	int index;
	UINT32 count;
	UINT32 status;
	ReaderStateA* readerState;

	call->rgReaderStates = NULL;

	status = smartcard_unpack_redir_scard_context(smartcard, s, &(call->Context));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 12)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeA_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->dwTimeOut); /* dwTimeOut (4 bytes) */
	Stream_Read_UINT32(s, call->cReaders); /* cReaders (4 bytes) */
	Stream_Seek_UINT32(s); /* rgReaderStatesNdrPtr (4 bytes) */

	status = smartcard_unpack_redir_scard_context_ref(smartcard, s, &(call->Context));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeA_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek_UINT32(s); /* NdrConformant (4 bytes) */

	if (call->cReaders > 0)
	{
		call->rgReaderStates = (ReaderStateA*) calloc(call->cReaders, sizeof(ReaderStateA));

		for (index = 0; index < call->cReaders; index++)
		{
			readerState = &call->rgReaderStates[index];

			if (Stream_GetRemainingLength(s) < 52)
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeA_Call is too short: %d",
						(int) Stream_GetRemainingLength(s));
				return SCARD_F_INTERNAL_ERROR;
			}

			Stream_Seek_UINT32(s); /* (4 bytes) */
			Stream_Read_UINT32(s, readerState->Common.dwCurrentState); /* dwCurrentState (4 bytes) */
			Stream_Read_UINT32(s, readerState->Common.dwEventState); /* dwEventState (4 bytes) */
			Stream_Read_UINT32(s, readerState->Common.cbAtr); /* cbAtr (4 bytes) */
			Stream_Read(s, readerState->Common.rgbAtr, 32); /* rgbAtr [0..32] (32 bytes) */
			Stream_Seek_UINT32(s); /* rgbAtr [32..36] (4 bytes) */

			/* reset high bytes? */
			readerState->Common.dwCurrentState &= 0x0000FFFF;
			readerState->Common.dwEventState = 0;
		}

		for (index = 0; index < call->cReaders; index++)
		{
			readerState = &call->rgReaderStates[index];

			if (Stream_GetRemainingLength(s) < 12)
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeA_Call is too short: %d",
						(int) Stream_GetRemainingLength(s));
				return SCARD_F_INTERNAL_ERROR;
			}

			Stream_Seek_UINT32(s); /* NdrMaxCount (4 bytes) */
			Stream_Seek_UINT32(s); /* NdrOffset (4 bytes) */
			Stream_Read_UINT32(s, count); /* NdrActualCount (4 bytes) */

			if (Stream_GetRemainingLength(s) < count)
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeA_Call is too short: %d",
						(int) Stream_GetRemainingLength(s));
				return SCARD_F_INTERNAL_ERROR;
			}

			readerState->szReader = malloc(count + 1);
			Stream_Read(s, readerState->szReader, count);
			smartcard_unpack_read_offset_align(smartcard, s, 4);
			readerState->szReader[count] = '\0';

			if (!readerState->szReader)
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeA_Call null reader name");
				return SCARD_F_INTERNAL_ERROR;
			}

			if (strcmp((char*) readerState->szReader, "\\\\?PnP?\\Notification") == 0)
			{
				readerState->Common.dwCurrentState |= SCARD_STATE_IGNORE;
			}
		}
	}

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_get_status_change_w_call(SMARTCARD_DEVICE* smartcard, wStream* s, GetStatusChangeW_Call* call)
{
	int index;
	UINT32 count;
	UINT32 status;
	ReaderStateW* readerState;

	call->rgReaderStates = NULL;

	status = smartcard_unpack_redir_scard_context(smartcard, s, &(call->Context));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 12)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeW_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->dwTimeOut); /* dwTimeOut (4 bytes) */
	Stream_Read_UINT32(s, call->cReaders); /* cReaders (4 bytes) */
	Stream_Seek_UINT32(s); /* rgReaderStatesNdrPtr (4 bytes) */

	status = smartcard_unpack_redir_scard_context_ref(smartcard, s, &(call->Context));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeW_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Seek_UINT32(s); /* NdrConformant (4 bytes) */

	if (call->cReaders > 0)
	{
		call->rgReaderStates = (ReaderStateW*) calloc(call->cReaders, sizeof(ReaderStateW));

		for (index = 0; index < call->cReaders; index++)
		{
			readerState = &call->rgReaderStates[index];

			if (Stream_GetRemainingLength(s) < 52)
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeW_Call is too short: %d",
						(int) Stream_GetRemainingLength(s));
				return SCARD_F_INTERNAL_ERROR;
			}

			Stream_Seek_UINT32(s); /* (4 bytes) */
			Stream_Read_UINT32(s, readerState->Common.dwCurrentState); /* dwCurrentState (4 bytes) */
			Stream_Read_UINT32(s, readerState->Common.dwEventState); /* dwEventState (4 bytes) */
			Stream_Read_UINT32(s, readerState->Common.cbAtr); /* cbAtr (4 bytes) */
			Stream_Read(s, readerState->Common.rgbAtr, 32); /* rgbAtr [0..32] (32 bytes) */
			Stream_Seek_UINT32(s); /* rgbAtr [32..36] (4 bytes) */

			/* reset high bytes? */
			readerState->Common.dwCurrentState &= 0x0000FFFF;
			readerState->Common.dwEventState = 0;
		}

		for (index = 0; index < call->cReaders; index++)
		{
			readerState = &call->rgReaderStates[index];

			if (Stream_GetRemainingLength(s) < 12)
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeW_Call is too short: %d",
						(int) Stream_GetRemainingLength(s));
				return SCARD_F_INTERNAL_ERROR;
			}

			Stream_Seek_UINT32(s); /* NdrMaxCount (4 bytes) */
			Stream_Seek_UINT32(s); /* NdrOffset (4 bytes) */
			Stream_Read_UINT32(s, count); /* NdrActualCount (4 bytes) */

			if (Stream_GetRemainingLength(s) < (count * 2))
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeW_Call is too short: %d",
						(int) Stream_GetRemainingLength(s));
				return SCARD_F_INTERNAL_ERROR;
			}

			readerState->szReader = malloc((count + 1) * 2);
			Stream_Read(s, readerState->szReader, (count * 2));
			smartcard_unpack_read_offset_align(smartcard, s, 4);
			readerState->szReader[count] = '\0';

			if (!readerState->szReader)
			{
				WLog_Print(smartcard->log, WLOG_WARN, "GetStatusChangeW_Call null reader name");
				return SCARD_F_INTERNAL_ERROR;
			}

#if 0
			if (strcmp((char*) readerState->szReader, "\\\\?PnP?\\Notification") == 0)
			{
				readerState->Common.dwCurrentState |= SCARD_STATE_IGNORE;
			}
#endif
		}
	}

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_state_call(SMARTCARD_DEVICE* smartcard, wStream* s, State_Call* call)
{
	UINT32 status;

	status = smartcard_unpack_redir_scard_handle(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 8)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "State_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->fpbAtrIsNULL); /* fpbAtrIsNULL (4 bytes) */
	Stream_Read_UINT32(s, call->cbAtrLen); /* cbAtrLen (4 bytes) */

	status = smartcard_unpack_redir_scard_handle_ref(smartcard, s, &(call->hCard));

	if (status)
		return status;

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_status_call(SMARTCARD_DEVICE* smartcard, wStream* s, Status_Call* call)
{
	UINT32 status;

	status = smartcard_unpack_redir_scard_handle(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 12)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Status_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->fmszReaderNamesIsNULL); /* fmszReaderNamesIsNULL (4 bytes) */
	Stream_Read_UINT32(s, call->cchReaderLen); /* cchReaderLen (4 bytes) */
	Stream_Read_UINT32(s, call->cbAtrLen); /* cbAtrLen (4 bytes) */

	status = smartcard_unpack_redir_scard_handle_ref(smartcard, s, &(call->hCard));

	if (status)
		return status;

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_get_attrib_call(SMARTCARD_DEVICE* smartcard, wStream* s, GetAttrib_Call* call)
{
	UINT32 status;

	status = smartcard_unpack_redir_scard_handle(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 12)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "GetAttrib_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->dwAttrId); /* dwAttrId (4 bytes) */
	Stream_Read_UINT32(s, call->fpbAttrIsNULL); /* fpbAttrIsNULL (4 bytes) */
	Stream_Read_UINT32(s, call->cbAttrLen); /* cbAttrLen (4 bytes) */

	status = smartcard_unpack_redir_scard_handle_ref(smartcard, s, &(call->hCard));

	if (status)
		return status;

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_control_call(SMARTCARD_DEVICE* smartcard, wStream* s, Control_Call* call)
{
	UINT32 status;
	UINT32 length;

	call->pvInBuffer = NULL;

	status = smartcard_unpack_redir_scard_handle(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 20)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Control_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, call->dwControlCode); /* dwControlCode (4 bytes) */
	Stream_Read_UINT32(s, call->cbInBufferSize); /* cbInBufferSize (4 bytes) */
	Stream_Seek_UINT32(s); /* pvInBufferNdrPtr (4 bytes) */
	Stream_Read_UINT32(s, call->fpvOutBufferIsNULL); /* fpvOutBufferIsNULL (4 bytes) */
	Stream_Read_UINT32(s, call->cbOutBufferSize); /* cbOutBufferSize (4 bytes) */

	status = smartcard_unpack_redir_scard_handle_ref(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (call->cbInBufferSize)
	{
		if (Stream_GetRemainingLength(s) < 4)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Control_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		Stream_Read_UINT32(s, length); /* Length (4 bytes) */

		if (Stream_GetRemainingLength(s) < length)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Control_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		call->pvInBuffer = (BYTE*) malloc(length);
		call->cbInBufferSize = length;

		Stream_Read(s, call->pvInBuffer, length);
	}

	return SCARD_S_SUCCESS;
}

UINT32 smartcard_unpack_transmit_call(SMARTCARD_DEVICE* smartcard, wStream* s, Transmit_Call* call)
{
	UINT32 status;
	UINT32 length;
	BYTE* pbExtraBytes;
	UINT32 pbExtraBytesNdrPtr;
	UINT32 pbSendBufferNdrPtr;
	UINT32 pioRecvPciNdrPtr;
	SCardIO_Request ioSendPci;
	SCardIO_Request ioRecvPci;

	call->pioSendPci = NULL;
	call->pioRecvPci = NULL;
	call->pbSendBuffer = NULL;

	status = smartcard_unpack_redir_scard_handle(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (Stream_GetRemainingLength(s) < 32)
	{
		WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call is too short: %d",
				(int) Stream_GetRemainingLength(s));
		return SCARD_F_INTERNAL_ERROR;
	}

	Stream_Read_UINT32(s, ioSendPci.dwProtocol); /* dwProtocol (4 bytes) */
	Stream_Read_UINT32(s, ioSendPci.cbExtraBytes); /* cbExtraBytes (4 bytes) */
	Stream_Read_UINT32(s, pbExtraBytesNdrPtr); /* pbExtraBytesNdrPtr (4 bytes) */
	Stream_Read_UINT32(s, call->cbSendLength); /* cbSendLength (4 bytes) */
	Stream_Read_UINT32(s, pbSendBufferNdrPtr); /* pbSendBufferNdrPtr (4 bytes) */
	Stream_Read_UINT32(s, pioRecvPciNdrPtr); /* pioRecvPciNdrPtr (4 bytes) */
	Stream_Read_UINT32(s, call->fpbRecvBufferIsNULL); /* fpbRecvBufferIsNULL (4 bytes) */
	Stream_Read_UINT32(s, call->cbRecvLength); /* cbRecvLength (4 bytes) */

	status = smartcard_unpack_redir_scard_handle_ref(smartcard, s, &(call->hCard));

	if (status)
		return status;

	if (pbExtraBytesNdrPtr)
	{
		if (Stream_GetRemainingLength(s) < 4)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		Stream_Read_UINT32(s, length); /* Length (4 bytes) */

		if (Stream_GetRemainingLength(s) < ioSendPci.cbExtraBytes)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		ioSendPci.pbExtraBytes = (BYTE*) Stream_Pointer(s);

		call->pioSendPci = (LPSCARD_IO_REQUEST) malloc(sizeof(SCARD_IO_REQUEST) + ioSendPci.cbExtraBytes);

		if (!call->pioSendPci)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call out of memory error (pioSendPci)");
			return SCARD_F_INTERNAL_ERROR;
		}

		call->pioSendPci->dwProtocol = ioSendPci.dwProtocol;
		call->pioSendPci->cbPciLength = ioSendPci.cbExtraBytes + sizeof(SCARD_IO_REQUEST);

		pbExtraBytes = &((BYTE*) call->pioSendPci)[sizeof(SCARD_IO_REQUEST)];
		CopyMemory(pbExtraBytes, ioSendPci.pbExtraBytes, ioSendPci.cbExtraBytes);
		Stream_Seek(s, ioSendPci.cbExtraBytes);
	}
	else
	{
		call->pioSendPci = (LPSCARD_IO_REQUEST) malloc(sizeof(SCARD_IO_REQUEST));

		if (!call->pioSendPci)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call out of memory error (pioSendPci)");
			return SCARD_F_INTERNAL_ERROR;
		}

		call->pioSendPci->dwProtocol = SCARD_PROTOCOL_T1;
		call->pioSendPci->cbPciLength = sizeof(SCARD_IO_REQUEST);
	}

	if (pbSendBufferNdrPtr)
	{
		if (Stream_GetRemainingLength(s) < 4)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		Stream_Read_UINT32(s, length); /* Length (4 bytes) */

		if (length < call->cbSendLength)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call unexpected length: Actual: %d, Expected: %d",
					(int) length, (int) call->cbSendLength);
			return SCARD_F_INTERNAL_ERROR;
		}

		if (Stream_GetRemainingLength(s) < call->cbSendLength)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		call->pbSendBuffer = (BYTE*) malloc(call->cbSendLength);

		if (!call->pbSendBuffer)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call out of memory error (pbSendBuffer)");
			return SCARD_F_INTERNAL_ERROR;
		}

		Stream_Read(s, call->pbSendBuffer, call->cbSendLength);
	}

	if (pioRecvPciNdrPtr)
	{
		if (Stream_GetRemainingLength(s) < 16)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		winpr_HexDump(Stream_Pointer(s), Stream_GetRemainingLength(s));

		Stream_Read_UINT32(s, length); /* Length (4 bytes) */

		Stream_Read_UINT32(s, ioRecvPci.dwProtocol); /* dwProtocol (4 bytes) */
		Stream_Read_UINT32(s, ioRecvPci.cbExtraBytes); /* cbExtraBytes (4 bytes) */
		Stream_Read_UINT32(s, pbExtraBytesNdrPtr); /* pbExtraBytesNdrPtr (4 bytes) */

		if (length < ioRecvPci.cbExtraBytes)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call unexpected length: Actual: %d, Expected: %d",
					(int) length, (int) ioRecvPci.cbExtraBytes);
			return SCARD_F_INTERNAL_ERROR;
		}

		if (Stream_GetRemainingLength(s) < ioRecvPci.cbExtraBytes)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call is too short: %d",
					(int) Stream_GetRemainingLength(s));
			return SCARD_F_INTERNAL_ERROR;
		}

		ioRecvPci.pbExtraBytes = (BYTE*) Stream_Pointer(s);

		call->pioRecvPci = (LPSCARD_IO_REQUEST) malloc(sizeof(SCARD_IO_REQUEST) + ioRecvPci.cbExtraBytes);

		if (!call->pbSendBuffer)
		{
			WLog_Print(smartcard->log, WLOG_WARN, "Transmit_Call out of memory error (pioRecvPci)");
			return SCARD_F_INTERNAL_ERROR;
		}

		call->pioRecvPci->dwProtocol = ioRecvPci.dwProtocol;
		call->pioRecvPci->cbPciLength = ioRecvPci.cbExtraBytes + sizeof(SCARD_IO_REQUEST);

		pbExtraBytes = &((BYTE*) call->pioRecvPci)[sizeof(SCARD_IO_REQUEST)];
		CopyMemory(pbExtraBytes, ioRecvPci.pbExtraBytes, ioRecvPci.cbExtraBytes);
		Stream_Seek(s, ioRecvPci.cbExtraBytes);
	}

	return SCARD_S_SUCCESS;
}