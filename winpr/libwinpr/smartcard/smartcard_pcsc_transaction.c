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

#include "../log.h"
#define TAG WINPR_TAG("smartcard")

/* pcsc-lite defines its error codes as ((LONG)0x8010xxxx). With a 64 bit LONG
 * they come back as large positive numbers and never compare equal to
 * WinSCard's negative 32 bit constants, so fold every result first. */
static PCSC_LONG pcsc_status(PCSC_LONG status)
{
	return (PCSC_LONG)(INT32)(UINT32)status;
}

struct pcsc_transaction_handle
{
	SCARDHANDLE hCard;
	char* szReader;
	DWORD dwDepth;

	/* The rest is protected by the table lock. A handle may be closed
	 * (SCardDisconnect) by one thread while another one waits in
	 * PCSC_TransactionBegin or PCSC_TransactionAcquire on it, so waiters hold
	 * a reference and the memory lives until the last of them has left. */
	UINT32 refs;
	BOOL closed;
};

/* Transaction state of one pcsc-lite reader */
typedef struct
{
	/* our handle currently inside the (emulated) transaction */
	PCSC_TRANSACTION_HANDLE* owner;
	/* owner holds pcsc-lite's reader lock */
	BOOL readerLocked;
	/* tick of the owner's last SCardBeginTransaction or card access */
	UINT64 lastActivity;
} pcsc_reader_transaction;

struct pcsc_transaction_table
{
	PCSC_TRANSACTION_OPS ops;
	CRITICAL_SECTION lock;
	/* pcsc-lite reader name -> pcsc_reader_transaction* */
	wHashTable* readers;
};

void PCSC_TransactionTableFree(PCSC_TRANSACTION_TABLE* table)
{
	if (!table)
		return;

	HashTable_Free(table->readers);
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
	table->readers = HashTable_New(FALSE);
	if (!table->readers || !HashTable_SetupForStringData(table->readers, FALSE))
		goto fail;

	{
		wObject* obj = HashTable_ValueObject(table->readers);
		if (!obj)
			goto fail;
		obj->fnObjectFree = free;
	}

	return table;

fail:
	PCSC_TransactionTableFree(table);
	return nullptr;
}

PCSC_TRANSACTION_HANDLE* PCSC_TransactionHandleNew(SCARDHANDLE hCard, const char* szReader)
{
	if (!szReader)
		return nullptr;

	PCSC_TRANSACTION_HANDLE* handle = calloc(1, sizeof(PCSC_TRANSACTION_HANDLE));
	if (!handle)
		return nullptr;

	handle->hCard = hCard;
	handle->refs = 1;
	handle->szReader = _strdup(szReader);
	if (!handle->szReader)
	{
		free(handle);
		return nullptr;
	}
	return handle;
}

/* Must be called with the table lock held */
static void handle_unref(PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(handle->refs > 0);
	if (--handle->refs > 0)
		return;

	free(handle->szReader);
	free(handle);
}

PCSC_TRANSACTION_HANDLE* PCSC_TransactionHandleRef(PCSC_TRANSACTION_TABLE* table,
                                                   PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	if (!handle)
		return nullptr;

	EnterCriticalSection(&table->lock);
	handle->refs++;
	LeaveCriticalSection(&table->lock);
	return handle;
}

void PCSC_TransactionHandleUnref(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	if (!handle)
		return;

	EnterCriticalSection(&table->lock);
	handle_unref(handle);
	LeaveCriticalSection(&table->lock);
}

/* Must be called with the table lock held */
static pcsc_reader_transaction* reader_transaction(PCSC_TRANSACTION_TABLE* table,
                                                   const char* szReader, BOOL create)
{
	pcsc_reader_transaction* reader = HashTable_GetItemValue(table->readers, szReader);
	if (reader || !create)
		return reader;

	reader = calloc(1, sizeof(pcsc_reader_transaction));
	if (!reader)
		return nullptr;

	if (!HashTable_Insert(table->readers, szReader, reader))
	{
		free(reader);
		return nullptr;
	}
	return reader;
}

/* Must be called with the table lock held. Gives up the reader lock pcsc-lite
 * holds for the current owner so that another handle can take it. */
static void release_reader_lock(PCSC_TRANSACTION_TABLE* table, pcsc_reader_transaction* reader,
                                PCSC_DWORD dwDisposition, PCSC_LONG* pStatus)
{
	WINPR_ASSERT(reader->owner);

	const PCSC_LONG status =
	    pcsc_status(table->ops.end(table->ops.context, reader->owner->hCard, dwDisposition));
	if (status != SCARD_S_SUCCESS)
		WLog_WARN(TAG, "[%s] hCard=%p SCardEndTransaction(disposition=%" PRIu32 ") failed: %s",
		          reader->owner->szReader, (void*)reader->owner->hCard, (UINT32)dwDisposition,
		          SCardGetErrorString((LONG)status));
	reader->readerLocked = FALSE;
	if (pStatus)
		*pStatus = status;
}

/* Must be called with the table lock held. Returns TRUE once handle is inside
 * the reader's transaction, FALSE if it has to wait for the current owner. */
static BOOL claim_transaction(PCSC_TRANSACTION_TABLE* table, pcsc_reader_transaction* reader,
                              PCSC_TRANSACTION_HANDLE* handle, UINT64 now, const char* what)
{
	PCSC_TRANSACTION_HANDLE* owner = reader->owner;

	if (owner == handle)
	{
		reader->lastActivity = now;
		return TRUE;
	}

	if (owner)
	{
		/* Wait while the owner uses the card. A handle that stopped accessing
		 * the card is treated like Windows treats it: its transaction is over. */
		if ((now - reader->lastActivity) < PCSC_TRANSACTION_IDLE_MS)
			return FALSE;

		if (reader->readerLocked)
			release_reader_lock(table, reader, SCARD_LEAVE_CARD, nullptr);

		WLog_DBG(TAG, "[%s] hCard=%p %s: takes transaction over from idle hCard=%p",
		         handle->szReader, (void*)handle->hCard, what, (void*)owner->hCard);
	}

	reader->owner = handle;
	reader->readerLocked = FALSE;
	reader->lastActivity = now;
	return TRUE;
}

void PCSC_TransactionHandleClose(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	if (!handle)
		return;

	EnterCriticalSection(&table->lock);
	handle->closed = TRUE;
	pcsc_reader_transaction* reader = reader_transaction(table, handle->szReader, FALSE);
	if (reader && reader->owner == handle)
	{
		/* pcsc-lite releases the reader lock itself when the handle goes away */
		reader->owner = nullptr;
		reader->readerLocked = FALSE;
	}
	WLog_DBG(TAG, "[%s] hCard=%p closed%s", handle->szReader, (void*)handle->hCard,
	         handle->refs > 1 ? ", waiters pending" : "");
	handle_unref(handle);
	LeaveCriticalSection(&table->lock);
}

PCSC_LONG PCSC_TransactionBegin(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	WINPR_ASSERT(handle);

	PCSC_LONG status = SCARD_S_SUCCESS;
	EnterCriticalSection(&table->lock);

	if (handle->closed)
	{
		status = SCARD_E_INVALID_HANDLE;
		goto out;
	}

	if (handle->dwDepth > 0)
	{
		handle->dwDepth++;
		WLog_DBG(TAG, "[%s] hCard=%p begin nested transaction, depth=%" PRIu32, handle->szReader,
		         (void*)handle->hCard, handle->dwDepth);
		goto out;
	}

	handle->refs++; /* we may wait and the handle may be closed meanwhile */
	for (;;)
	{
		if (handle->closed)
		{
			WLog_DBG(TAG, "[%s] hCard=%p closed while waiting to begin a transaction",
			         handle->szReader, (void*)handle->hCard);
			status = SCARD_E_INVALID_HANDLE;
			break;
		}

		pcsc_reader_transaction* reader = reader_transaction(table, handle->szReader, TRUE);
		if (!reader)
		{
			status = SCARD_E_NO_MEMORY;
			break;
		}

		const UINT64 now = table->ops.tick(table->ops.context);
		if (claim_transaction(table, reader, handle, now, "begin"))
		{
			handle->dwDepth = 1;
			WLog_DBG(TAG, "[%s] hCard=%p begin transaction", handle->szReader,
			         (void*)handle->hCard);
			break;
		}

		LeaveCriticalSection(&table->lock);
		table->ops.sleep(table->ops.context, PCSC_TRANSACTION_POLL_MS);
		EnterCriticalSection(&table->lock);
	}
	handle_unref(handle);

out:
	LeaveCriticalSection(&table->lock);
	return status;
}

PCSC_LONG PCSC_TransactionEnd(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle,
                              PCSC_DWORD dwDisposition)
{
	WINPR_ASSERT(table);
	WINPR_ASSERT(handle);

	PCSC_LONG status = SCARD_S_SUCCESS;
	EnterCriticalSection(&table->lock);

	if (handle->closed)
	{
		status = SCARD_E_INVALID_HANDLE;
		goto out;
	}

	if (handle->dwDepth == 0)
	{
		WLog_WARN(TAG, "[%s] hCard=%p end transaction without begin", handle->szReader,
		          (void*)handle->hCard);
		status = SCARD_E_NOT_TRANSACTED;
		goto out;
	}

	handle->dwDepth--;
	if (handle->dwDepth > 0)
	{
		WLog_DBG(TAG, "[%s] hCard=%p end nested transaction, depth=%" PRIu32, handle->szReader,
		         (void*)handle->hCard, handle->dwDepth);
		goto out;
	}

	pcsc_reader_transaction* reader = reader_transaction(table, handle->szReader, FALSE);
	if (reader && reader->owner == handle)
	{
		/* pcsc-lite performs the card action even for an unlocked reader */
		if (reader->readerLocked || dwDisposition != SCARD_LEAVE_CARD)
			release_reader_lock(table, reader, dwDisposition, &status);
		reader->owner = nullptr;
		WLog_DBG(TAG, "[%s] hCard=%p end transaction, disposition=%" PRIu32 " -> %s",
		         handle->szReader, (void*)handle->hCard, (UINT32)dwDisposition,
		         SCardGetErrorString((LONG)status));
	}
	else if (dwDisposition != SCARD_LEAVE_CARD)
	{
		/* The transaction was taken over, but the card action is still due.
		 * pcscd refuses it with SCARD_E_SHARING_VIOLATION while the new owner
		 * holds the reader lock, which is the honest answer. */
		status = pcsc_status(table->ops.end(table->ops.context, handle->hCard, dwDisposition));
		WLog_DBG(TAG, "[%s] hCard=%p end taken over transaction, disposition=%" PRIu32 " -> %s",
		         handle->szReader, (void*)handle->hCard, (UINT32)dwDisposition,
		         SCardGetErrorString((LONG)status));
	}
	else
	{
		WLog_DBG(TAG, "[%s] hCard=%p end taken over transaction", handle->szReader,
		         (void*)handle->hCard);
	}

out:
	LeaveCriticalSection(&table->lock);
	return status;
}

PCSC_LONG PCSC_TransactionAcquire(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle)
{
	WINPR_ASSERT(table);
	WINPR_ASSERT(handle);

	PCSC_LONG status = SCARD_S_SUCCESS;
	BOOL foreignWait = FALSE;
	UINT64 foreignSince = 0;

	EnterCriticalSection(&table->lock);

	if (handle->closed)
	{
		status = SCARD_E_INVALID_HANDLE;
		goto out;
	}

	if (handle->dwDepth == 0)
		goto out; /* plain shared access, nothing to lock */

	handle->refs++; /* we may wait and the handle may be closed meanwhile */
	for (;;)
	{
		if (handle->closed)
		{
			WLog_DBG(TAG, "[%s] hCard=%p closed while waiting for card access", handle->szReader,
			         (void*)handle->hCard);
			status = SCARD_E_INVALID_HANDLE;
			break;
		}

		pcsc_reader_transaction* reader = reader_transaction(table, handle->szReader, TRUE);
		if (!reader)
		{
			status = SCARD_E_NO_MEMORY;
			break;
		}

		const UINT64 now = table->ops.tick(table->ops.context);
		if (!claim_transaction(table, reader, handle, now, "card access"))
		{
			/* another handle holds the transaction and is using the card */
			LeaveCriticalSection(&table->lock);
			table->ops.sleep(table->ops.context, PCSC_TRANSACTION_POLL_MS);
			EnterCriticalSection(&table->lock);
			continue;
		}

		if (reader->readerLocked)
		{
			status = SCARD_S_SUCCESS;
			break;
		}

		/* pcsc-lite's SCardBeginTransaction blocks until the lock is free, so
		 * only call it once a non-blocking probe says a foreign application does
		 * not hold the lock. The probe also reports a reset or removed card. */
		status = pcsc_status(table->ops.probe(table->ops.context, handle->hCard));
		if (status == SCARD_S_SUCCESS)
		{
			status = pcsc_status(table->ops.begin(table->ops.context, handle->hCard));
			if (status == SCARD_S_SUCCESS)
				reader->readerLocked = TRUE;
			WLog_DBG(TAG, "[%s] hCard=%p reader lock -> %s%s", handle->szReader,
			         (void*)handle->hCard, SCardGetErrorString((LONG)status),
			         foreignWait ? " (after waiting for another application)" : "");
		}

		if (status != SCARD_E_SHARING_VIOLATION)
			break;

		if (!foreignWait)
		{
			foreignWait = TRUE;
			foreignSince = now;
			WLog_DBG(TAG, "[%s] hCard=%p reader locked by another application, waiting",
			         handle->szReader, (void*)handle->hCard);
		}
		else if (now - foreignSince >= PCSC_TRANSACTION_WAIT_MS)
		{
			WLog_WARN(TAG,
			          "[%s] hCard=%p reader locked by another application for %" PRIu32
			          " ms, giving up",
			          handle->szReader, (void*)handle->hCard, (UINT32)PCSC_TRANSACTION_WAIT_MS);
			break;
		}

		LeaveCriticalSection(&table->lock);
		table->ops.sleep(table->ops.context, PCSC_TRANSACTION_POLL_MS);
		EnterCriticalSection(&table->lock);
	}
	handle_unref(handle);

out:
	LeaveCriticalSection(&table->lock);
	return status;
}
