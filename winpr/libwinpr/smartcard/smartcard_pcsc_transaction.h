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

#ifndef WINPR_SMARTCARD_PCSC_TRANSACTION_PRIVATE_H
#define WINPR_SMARTCARD_PCSC_TRANSACTION_PRIVATE_H

#include <winpr/wtypes.h>
#include <winpr/smartcard.h>

#include "smartcard_pcsc.h"

/**
 * WinSCard transactions emulated on top of pcsc-lite's reader lock.
 *
 * A redirected Windows client runs transactions from many contexts at once
 * and relies on SCardBeginTransaction blocking until the reader is free, but
 * forwarding it to pcsc-lite does not work: pcsc-lite locks the reader for one
 * card handle, its client library retries SCardBeginTransaction forever on
 * SCARD_E_SHARING_VIOLATION, and all calls of one context are processed by a
 * single thread, so a blocked SCardBeginTransaction can sit in front of the
 * SCardEndTransaction that would release the lock.
 *
 * So the transaction itself is emulated here, per reader:
 * - SCardBeginTransaction takes a virtual lock shared by all of our handles.
 *   If another handle holds it, we wait while that handle is active. A
 *   holder idle for PCSC_TRANSACTION_IDLE_MS (Windows drops such transactions
 *   too) loses the transaction and waits again on its next card access.
 *   The smartcard channel runs SCardBeginTransaction off its per context
 *   thread, so waiting here never blocks the holder's calls.
 * - pcsc-lite's reader lock is only taken by the first card I/O inside the
 *   transaction and released by SCardEndTransaction. Other applications see
 *   the reader locked only while the client actually accesses the card.
 * - Only a foreign application holding the reader lock makes card I/O wait,
 *   bounded by PCSC_TRANSACTION_WAIT_MS.
 */

/** How long card I/O inside a transaction waits for another application to
 *  release the reader lock before failing with SCARD_E_SHARING_VIOLATION. */
#define PCSC_TRANSACTION_WAIT_MS 5000
/** A transaction of one of our handles without card access for this long is
 *  taken over by a waiting handle. Windows uses the same five seconds. */
#define PCSC_TRANSACTION_IDLE_MS 5000
/** Poll interval while waiting, matches pcsc-lite's PCSCLITE_LOCK_POLL_RATE. */
#define PCSC_TRANSACTION_POLL_MS 100

typedef struct
{
	void* context;
	/** pcsc-lite SCardBeginTransaction */
	PCSC_LONG (*begin)(void* context, SCARDHANDLE hCard);
	/** pcsc-lite SCardEndTransaction */
	PCSC_LONG (*end)(void* context, SCARDHANDLE hCard, PCSC_DWORD dwDisposition);
	/** Non-blocking check whether another handle holds the reader lock:
	 *  returns SCARD_E_SHARING_VIOLATION if so (pcsc-lite SCardStatus with
	 *  PCSCLITE_NO_BLOCKING set) */
	PCSC_LONG (*probe)(void* context, SCARDHANDLE hCard);
	/** Called without any lock held */
	void (*sleep)(void* context, UINT32 ms);
	/** Monotonic milliseconds */
	UINT64 (*tick)(void* context);
} PCSC_TRANSACTION_OPS;

typedef struct pcsc_transaction_table PCSC_TRANSACTION_TABLE;

typedef struct
{
	SCARDHANDLE hCard;
	char* szReader;
	DWORD dwDepth;
} PCSC_TRANSACTION_HANDLE;

void PCSC_TransactionTableFree(PCSC_TRANSACTION_TABLE* table);

WINPR_ATTR_MALLOC(PCSC_TransactionTableFree, 1)
PCSC_TRANSACTION_TABLE* PCSC_TransactionTableNew(const PCSC_TRANSACTION_OPS* ops);

/** Associate a card handle with the pcsc-lite reader name it is connected to */
BOOL PCSC_TransactionHandleInit(PCSC_TRANSACTION_HANDLE* handle, SCARDHANDLE hCard,
                                const char* szReader);
/** Drop any transaction of the handle (pcsc-lite releases the reader lock
 *  itself on SCardDisconnect) and free its resources */
void PCSC_TransactionHandleUninit(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle);

/** SCardBeginTransaction: waits for another of our handles, never calls pcsc-lite */
PCSC_LONG PCSC_TransactionBegin(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle);
/** SCardEndTransaction: releases the reader lock if held, forwards dwDisposition */
PCSC_LONG PCSC_TransactionEnd(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle,
                              PCSC_DWORD dwDisposition);
/** Call before card I/O: inside a transaction, makes sure the handle holds
 *  the transaction and the reader lock. Returns SCARD_E_SHARING_VIOLATION if
 *  a foreign application keeps the lock for longer than
 *  PCSC_TRANSACTION_WAIT_MS. */
PCSC_LONG PCSC_TransactionAcquire(PCSC_TRANSACTION_TABLE* table, PCSC_TRANSACTION_HANDLE* handle);

#endif /* WINPR_SMARTCARD_PCSC_TRANSACTION_PRIVATE_H */
