/**
 * WinPR: Windows Portable Runtime
 * Smart Card API - PCSC transaction emulation
 *
 * Copyright 2026 Dennis S. <1518323+Skinner927@users.noreply.github.com>
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

#include <winpr/config.h>

#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/collections.h>

#include "smartcard_pcsc_transaction.h"

struct pcsc_transaction_table
{
	PCSC_TRANSACTION_OPS ops;
	CRITICAL_SECTION lock;
	/* pcsc-lite reader name -> PCSC_TRANSACTION_HANDLE* holding the reader lock */
	wHashTable* owners;
};

void PCSC_TransactionTableFree(PCSC_TRANSACTION_TABLE* table)
{
	if (!table)
		return;

	HashTable_Free(table->owners);
	DeleteCriticalSection(&table->lock);
	free(table);
}

PCSC_TRANSACTION_TABLE* PCSC_TransactionTableNew(const PCSC_TRANSACTION_OPS* ops)
{
	WINPR_ASSERT(ops);

	PCSC_TRANSACTION_TABLE* table = calloc(1, sizeof(PCSC_TRANSACTION_TABLE));
	if (!table)
		return nullptr;

	table->ops = *ops;
	InitializeCriticalSection(&table->lock);
	table->owners = HashTable_New(FALSE);
	if (!table->owners || !HashTable_SetupForStringData(table->owners, FALSE))
	{
		PCSC_TransactionTableFree(table);
		return nullptr;
	}

	return table;
}

BOOL PCSC_TransactionHandleInit(PCSC_TRANSACTION_HANDLE* handle, SCARDHANDLE hCard,
                                const char* szReader)
{
	WINPR_ASSERT(handle);

	if (!szReader)
		return FALSE;

	handle->hCard = hCard;
	handle->dwDepth = 0;
	handle->szReader = _strdup(szReader);
	return handle->szReader != nullptr;
}

void PCSC_TransactionHandleUninit(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	if (!handle || !handle->szReader)
		return;

	EnterCriticalSection(&table->lock);
	if (HashTable_GetItemValue(table->owners, handle->szReader) == handle)
		HashTable_Remove(table->owners, handle->szReader);
	LeaveCriticalSection(&table->lock);

	free(handle->szReader);
	handle->szReader = nullptr;
	handle->dwDepth = 0;
}

PCSC_LONG PCSC_TransactionBegin(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	WINPR_ASSERT(handle);

	EnterCriticalSection(&table->lock);
	handle->dwDepth++;
	LeaveCriticalSection(&table->lock);
	return SCARD_S_SUCCESS;
}

PCSC_LONG PCSC_TransactionEnd(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle,
                              PCSC_DWORD dwDisposition)
{
	WINPR_ASSERT(table);
	WINPR_ASSERT(handle);

	PCSC_LONG status = SCARD_S_SUCCESS;
	EnterCriticalSection(&table->lock);

	if (handle->dwDepth == 0)
	{
		status = SCARD_E_NOT_TRANSACTED;
		goto out;
	}

	handle->dwDepth--;
	if (handle->dwDepth > 0)
		goto out;

	PCSC_TRANSACTION_HANDLE* owner = HashTable_GetItemValue(table->owners, handle->szReader);
	if (owner == handle)
	{
		status = table->ops.end(table->ops.context, handle->hCard, dwDisposition);
		HashTable_Remove(table->owners, handle->szReader);
	}
	else if (dwDisposition != SCARD_LEAVE_CARD)
	{
		/* The card action is still due even though this handle never took the
		 * lock. pcscd performs it for an unlocked reader, so give up a lock held
		 * by another of our handles first; a foreign holder makes pcscd answer
		 * SCARD_E_SHARING_VIOLATION, which is the honest result. */
		if (owner)
		{
			table->ops.end(table->ops.context, owner->hCard, SCARD_LEAVE_CARD);
			HashTable_Remove(table->owners, handle->szReader);
		}
		status = table->ops.end(table->ops.context, handle->hCard, dwDisposition);
	}

out:
	LeaveCriticalSection(&table->lock);
	return status;
}

PCSC_LONG PCSC_TransactionAcquire(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	WINPR_ASSERT(handle);

	if (handle->dwDepth == 0)
		return SCARD_S_SUCCESS; /* plain shared access, nothing to lock */

	const UINT64 start = table->ops.tick(table->ops.context);

	for (;;)
	{
		PCSC_LONG status = SCARD_S_SUCCESS;
		EnterCriticalSection(&table->lock);

		PCSC_TRANSACTION_HANDLE* owner = HashTable_GetItemValue(table->owners, handle->szReader);
		if (owner == handle)
			goto out; /* already holding the reader lock */

		if (owner)
		{
			/* Another of our handles holds the reader lock. Its transaction stays
			 * open for us, but pcsc-lite's lock moves to the handle doing I/O now:
			 * waiting for the owner could deadlock, its SCardEndTransaction may be
			 * queued behind this very call. */
			table->ops.end(table->ops.context, owner->hCard, SCARD_LEAVE_CARD);
			HashTable_Remove(table->owners, handle->szReader);
		}

		/* pcsc-lite's SCardBeginTransaction blocks until the lock is free, so
		 * only call it once a non-blocking probe says a foreign application does
		 * not hold the lock. The probe also reports a reset or removed card. */
		status = table->ops.probe(table->ops.context, handle->hCard);
		if (status == SCARD_S_SUCCESS)
		{
			status = table->ops.begin(table->ops.context, handle->hCard);
			if (status == SCARD_S_SUCCESS)
			{
				if (!HashTable_Insert(table->owners, handle->szReader, handle))
					status = SCARD_E_NO_MEMORY;
			}
		}

		if (status != SCARD_E_SHARING_VIOLATION)
			goto out;

		LeaveCriticalSection(&table->lock);

		if (table->ops.tick(table->ops.context) - start >= PCSC_TRANSACTION_WAIT_MS)
			return SCARD_E_SHARING_VIOLATION;

		table->ops.sleep(table->ops.context, PCSC_TRANSACTION_POLL_MS);
		continue;

	out:
		LeaveCriticalSection(&table->lock);
		return status;
	}
}
