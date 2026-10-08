/**
 * Unit test for the PCSC transaction emulation in smartcard_pcsc_transaction.c
 *
 * Simulates pcsc-lite's per reader lock: a fake card handle encodes its reader
 * in the upper bits (hCard >> 8), the fake daemon tracks one lock owner per
 * reader and the fake clock advances only when the code under test sleeps.
 * Sleeping may also run one scheduled SCardEndTransaction, standing in for
 * another context thread ending its transaction while we wait.
 */

#include <stdio.h>
#include <string.h>

#include <winpr/crt.h>

#include "../smartcard_pcsc_transaction.h"

#define FAKE_READERS 4
#define FAKE_READER(hCard) ((size_t)((hCard) >> 8) & (FAKE_READERS - 1))

/* A handle that belongs to some other application sharing the reader */
#define FOREIGN_HANDLE(reader) ((SCARDHANDLE)(((reader) << 8) | 0xFF))

typedef struct
{
	SCARDHANDLE lockOwner[FAKE_READERS];
	UINT64 now;
	UINT64 foreignReleaseAt; /* the foreign holder lets go at this time, 0 = never */

	size_t beginCalls;
	size_t endCalls;
	size_t probeCalls;
	size_t sleepCalls;
	SCARDHANDLE lastBegin;
	SCARDHANDLE lastEnd;
	PCSC_DWORD lastEndDisposition;
} fake_pcsc;

typedef struct
{
	fake_pcsc fake;
	PCSC_TRANSACTION_OPS ops;
	PCSC_TRANSACTION_TABLE* table;

	/* another context acts on this handle at this time: ends its transaction
	 * or closes it (SCardDisconnect) */
	PCSC_TRANSACTION_HANDLE* actionHandle;
	SCARDHANDLE actionCard;
	UINT64 actionAt;
	BOOL actionClose;
	PCSC_LONG endStatus;
} fixture;

/* pcsc-lite hands out its error codes as ((LONG)0x8010xxxx) with a 64 bit
 * LONG on most platforms, so they arrive as large positive numbers, unlike
 * WinSCard's negative 32 bit values. */
static PCSC_LONG raw(LONG winscardCode)
{
	return (PCSC_LONG)(UINT32)winscardCode;
}

static void fake_release_foreign(fake_pcsc* fake, size_t reader)
{
	if (fake->foreignReleaseAt && fake->now >= fake->foreignReleaseAt &&
	    fake->lockOwner[reader] == FOREIGN_HANDLE(reader))
		fake->lockOwner[reader] = 0;
}

static PCSC_LONG fake_begin(void* context, SCARDHANDLE hCard)
{
	fake_pcsc* fake = &((fixture*)context)->fake;
	const size_t reader = FAKE_READER(hCard);
	fake->beginCalls++;
	fake->lastBegin = hCard;
	fake_release_foreign(fake, reader);
	if (fake->lockOwner[reader] != 0 && fake->lockOwner[reader] != hCard)
		return raw(SCARD_E_SHARING_VIOLATION);
	fake->lockOwner[reader] = hCard;
	return SCARD_S_SUCCESS;
}

static PCSC_LONG fake_end(void* context, SCARDHANDLE hCard, PCSC_DWORD dwDisposition)
{
	fake_pcsc* fake = &((fixture*)context)->fake;
	const size_t reader = FAKE_READER(hCard);
	fake->endCalls++;
	fake->lastEnd = hCard;
	fake->lastEndDisposition = dwDisposition;
	fake_release_foreign(fake, reader);
	/* pcscd: a handle that does not hold the lock may not end a transaction
	 * nor reset the card while someone else holds it */
	if (fake->lockOwner[reader] != 0 && fake->lockOwner[reader] != hCard)
		return raw(SCARD_E_SHARING_VIOLATION);
	fake->lockOwner[reader] = 0;
	return SCARD_S_SUCCESS;
}

static PCSC_LONG fake_probe(void* context, SCARDHANDLE hCard)
{
	fake_pcsc* fake = &((fixture*)context)->fake;
	const size_t reader = FAKE_READER(hCard);
	fake->probeCalls++;
	fake_release_foreign(fake, reader);
	if (fake->lockOwner[reader] != 0 && fake->lockOwner[reader] != hCard)
		return raw(SCARD_E_SHARING_VIOLATION);
	return SCARD_S_SUCCESS;
}

static void fake_sleep(void* context, UINT32 ms)
{
	fixture* f = context;
	f->fake.sleepCalls++;
	f->fake.now += ms;
	if (f->actionHandle && f->fake.now >= f->actionAt)
	{
		PCSC_TRANSACTION_HANDLE* handle = f->actionHandle;
		f->actionHandle = nullptr;
		if (f->actionClose)
		{
			/* pcscd releases the reader lock of a disconnected handle itself */
			if (f->fake.lockOwner[FAKE_READER(f->actionCard)] == f->actionCard)
				f->fake.lockOwner[FAKE_READER(f->actionCard)] = 0;
			PCSC_TransactionHandleClose(f->table, handle);
		}
		else
			f->endStatus = PCSC_TransactionEnd(f->table, handle, SCARD_LEAVE_CARD);
	}
}

static UINT64 fake_tick(void* context)
{
	return ((fixture*)context)->fake.now;
}

static BOOL fixture_init(fixture* f)
{
	memset(f, 0, sizeof(*f));
	f->ops.context = f;
	f->ops.begin = fake_begin;
	f->ops.end = fake_end;
	f->ops.probe = fake_probe;
	f->ops.sleep = fake_sleep;
	f->ops.tick = fake_tick;
	f->table = PCSC_TransactionTableNew(&f->ops);
	return f->table != nullptr;
}

static void fixture_uninit(fixture* f)
{
	PCSC_TransactionTableFree(f->table);
}

static void fixture_end_later(fixture* f, PCSC_TRANSACTION_HANDLE* handle, UINT64 at)
{
	f->actionHandle = handle;
	f->actionAt = at;
	f->actionClose = FALSE;
	f->endStatus = SCARD_F_INTERNAL_ERROR;
}

static void fixture_close_later(fixture* f, PCSC_TRANSACTION_HANDLE* handle, SCARDHANDLE hCard,
                                UINT64 at)
{
	f->actionHandle = handle;
	f->actionCard = hCard;
	f->actionAt = at;
	f->actionClose = TRUE;
}

#define CHECK(cond)                                                                        \
	do                                                                                     \
	{                                                                                      \
		if (!(cond))                                                                       \
		{                                                                                  \
			(void)fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __func__, __LINE__, #cond); \
			return FALSE;                                                                  \
		}                                                                                  \
	} while (0)

static BOOL test_begin_does_not_touch_pcsc(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);

	CHECK(f.fake.beginCalls == 0);
	CHECK(f.fake.probeCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_io_outside_transaction_does_not_lock(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);

	CHECK(f.fake.beginCalls == 0);
	CHECK(f.fake.probeCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_first_io_in_transaction_takes_lock_once(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);

	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);
	CHECK(f.fake.lastBegin == 0x101);
	CHECK(f.fake.lockOwner[1] == 0x101);

	/* further I/O in the same transaction reuses the lock */
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);
	CHECK(f.fake.sleepCalls == 0);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_end_releases_lock_with_disposition(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);

	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_RESET_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_RESET_CARD);
	CHECK(f.fake.lockOwner[1] == 0);

	/* I/O after the transaction is plain shared access again */
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_unbalanced_end_is_rejected(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_E_NOT_TRANSACTED);
	CHECK(f.fake.endCalls == 0);

	/* the handle is still usable afterwards */
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);
	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_begin_waits_for_holder_in_other_context(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x102, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);

	/* B's Begin blocks on its own context thread until A ends after 300ms */
	fixture_end_later(&f, a, 300);
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.actionHandle == nullptr);
	CHECK(f.endStatus == SCARD_S_SUCCESS);
	CHECK(f.fake.sleepCalls == 3);
	CHECK(f.fake.now == 300);
	/* A released the reader lock itself, nothing was taken away from it */
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lockOwner[1] == 0);
	CHECK(f.fake.beginCalls == 1);

	CHECK(PCSC_TransactionAcquire(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(f.fake.beginCalls == 2);
	CHECK(PCSC_TransactionEnd(f.table, b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleClose(f.table, a);
	PCSC_TransactionHandleClose(f.table, b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_idle_holder_in_other_context_is_taken_over(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x102, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);

	/* A never ends: after PCSC_TRANSACTION_IDLE_MS without card access B takes over */
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.now == PCSC_TRANSACTION_IDLE_MS);
	CHECK(f.fake.sleepCalls == PCSC_TRANSACTION_IDLE_MS / PCSC_TRANSACTION_POLL_MS);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_LEAVE_CARD);
	CHECK(f.fake.lockOwner[1] == 0);

	CHECK(PCSC_TransactionAcquire(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(f.fake.beginCalls == 2);

	/* A's transaction is still open; its next I/O waits for B, which is active */
	fixture_end_later(&f, b, f.fake.now + 300);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.actionHandle == nullptr);
	CHECK(f.endStatus == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 2);
	CHECK(f.fake.lastEnd == 0x102);
	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(f.fake.beginCalls == 3);

	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 3);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleClose(f.table, a);
	PCSC_TransactionHandleClose(f.table, b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_begin_waits_for_holder_in_same_context(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x102, "Reader 1")) != nullptr);

	/* Two handles of one context: the channel runs SCardBeginTransaction on a
	 * worker thread, so A's calls keep flowing while B waits for A to end.
	 * The emulation itself does not care which context a handle belongs to. */
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	fixture_end_later(&f, a, 200);
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.actionHandle == nullptr);
	CHECK(f.fake.sleepCalls == 2);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lockOwner[1] == 0);

	CHECK(PCSC_TransactionAcquire(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(PCSC_TransactionEnd(f.table, b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleClose(f.table, a);
	PCSC_TransactionHandleClose(f.table, b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_different_readers_lock_independently(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x201, "Reader 2")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.sleepCalls == 0);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, b) == SCARD_S_SUCCESS);

	/* both locks are held at the same time, nothing was handed over */
	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(f.fake.lockOwner[2] == 0x201);
	CHECK(f.fake.beginCalls == 2);
	CHECK(f.fake.endCalls == 0);

	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0);
	CHECK(f.fake.lockOwner[2] == 0x201);
	CHECK(PCSC_TransactionEnd(f.table, b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[2] == 0);

	PCSC_TransactionHandleClose(f.table, a);
	PCSC_TransactionHandleClose(f.table, b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_waits_for_foreign_holder_to_release(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);

	/* some other application holds the reader lock for 300ms */
	f.fake.lockOwner[1] = FOREIGN_HANDLE(1);
	f.fake.foreignReleaseAt = 300;

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);

	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(f.fake.sleepCalls == 3);
	CHECK(f.fake.now == 300);
	/* the blocking pcsc-lite call is only made once the lock is free */
	CHECK(f.fake.beginCalls == 1);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_gives_up_on_foreign_holder_after_timeout(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);

	/* some other application holds the reader lock and never lets go */
	f.fake.lockOwner[1] = FOREIGN_HANDLE(1);
	f.fake.foreignReleaseAt = 0;

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_E_SHARING_VIOLATION);

	CHECK(f.fake.now == PCSC_TRANSACTION_WAIT_MS);
	CHECK(f.fake.sleepCalls == PCSC_TRANSACTION_WAIT_MS / PCSC_TRANSACTION_POLL_MS);
	CHECK(f.fake.beginCalls == 0);
	CHECK(f.fake.lockOwner[1] == FOREIGN_HANDLE(1));

	/* the transaction is still open; once the holder is gone I/O works */
	f.fake.lockOwner[1] = 0;
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_end_with_reset_forwards_even_without_lock(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x102, "Reader 1")) != nullptr);

	/* A never did any I/O, so it holds no reader lock, but asks for a reset */
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_RESET_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_RESET_CARD);

	/* A lost its transaction to B (idle for too long) and asks for a reset
	 * while B holds the reader lock: pcscd refuses, which is passed on */
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.now == PCSC_TRANSACTION_IDLE_MS);
	CHECK(f.fake.lockOwner[1] == 0);
	CHECK(PCSC_TransactionAcquire(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_UNPOWER_CARD) == SCARD_E_SHARING_VIOLATION);
	CHECK(f.fake.lockOwner[1] == 0x102);

	/* once B is done, A's reset request goes through without a lock */
	CHECK(PCSC_TransactionEnd(f.table, b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0);
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_UNPOWER_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_UNPOWER_CARD);

	PCSC_TransactionHandleClose(f.table, a);
	PCSC_TransactionHandleClose(f.table, b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_disconnect_drops_transaction(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x102, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);

	/* SCardDisconnect while in a transaction: pcscd released the lock itself */
	PCSC_TransactionHandleClose(f.table, a);
	f.fake.lockOwner[1] = 0;
	CHECK(f.fake.endCalls == 0);

	/* B neither waits for the dead handle nor tries to release its lock */
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.sleepCalls == 0);
	CHECK(PCSC_TransactionAcquire(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(PCSC_TransactionEnd(f.table, b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);

	PCSC_TransactionHandleClose(f.table, b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_nested_transaction_releases_on_outermost_end(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);

	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0x101);

	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_waiting_begin_fails_when_its_handle_is_closed(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x102, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);

	/* B is disconnected by another thread while its Begin waits for A */
	fixture_close_later(&f, b, 0x102, 200);
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_E_INVALID_HANDLE);
	CHECK(f.actionHandle == nullptr);
	CHECK(f.fake.sleepCalls == 2);
	/* A was not disturbed */
	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(f.fake.endCalls == 0);
	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);

	PCSC_TransactionHandleClose(f.table, a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_waiting_begin_proceeds_when_holder_is_closed(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	PCSC_TRANSACTION_HANDLE* b = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK((b = PCSC_TransactionHandleNew(0x102, "Reader 1")) != nullptr);

	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);

	/* A is disconnected while B waits for it: B gets the transaction */
	fixture_close_later(&f, a, 0x101, 200);
	CHECK(PCSC_TransactionBegin(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.actionHandle == nullptr);
	CHECK(f.fake.sleepCalls == 2);
	CHECK(f.fake.endCalls == 0);
	CHECK(PCSC_TransactionAcquire(f.table, b) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(PCSC_TransactionEnd(f.table, b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);

	PCSC_TransactionHandleClose(f.table, b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_reference_outlives_close(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE* a = nullptr;
	CHECK(fixture_init(&f));
	CHECK((a = PCSC_TransactionHandleNew(0x101, "Reader 1")) != nullptr);
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_S_SUCCESS);

	/* a caller looked the handle up and holds a reference while SCardDisconnect
	 * closes it: the state stays valid, calls on it fail cleanly */
	CHECK(PCSC_TransactionHandleRef(f.table, a) == a);
	PCSC_TransactionHandleClose(f.table, a);
	CHECK(f.fake.lockOwner[1] == 0x101); /* pcscd releases it, not us */
	CHECK(PCSC_TransactionBegin(f.table, a) == SCARD_E_INVALID_HANDLE);
	CHECK(PCSC_TransactionAcquire(f.table, a) == SCARD_E_INVALID_HANDLE);
	CHECK(PCSC_TransactionEnd(f.table, a, SCARD_LEAVE_CARD) == SCARD_E_INVALID_HANDLE);
	CHECK(f.fake.endCalls == 0);
	PCSC_TransactionHandleUnref(f.table, a);

	fixture_uninit(&f);
	return TRUE;
}

int TestSmartCardPcscTransaction(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (!test_begin_does_not_touch_pcsc())
		return -1;
	if (!test_io_outside_transaction_does_not_lock())
		return -1;
	if (!test_first_io_in_transaction_takes_lock_once())
		return -1;
	if (!test_end_releases_lock_with_disposition())
		return -1;
	if (!test_unbalanced_end_is_rejected())
		return -1;
	if (!test_begin_waits_for_holder_in_other_context())
		return -1;
	if (!test_idle_holder_in_other_context_is_taken_over())
		return -1;
	if (!test_begin_waits_for_holder_in_same_context())
		return -1;
	if (!test_different_readers_lock_independently())
		return -1;
	if (!test_waits_for_foreign_holder_to_release())
		return -1;
	if (!test_gives_up_on_foreign_holder_after_timeout())
		return -1;
	if (!test_end_with_reset_forwards_even_without_lock())
		return -1;
	if (!test_disconnect_drops_transaction())
		return -1;
	if (!test_nested_transaction_releases_on_outermost_end())
		return -1;
	if (!test_waiting_begin_fails_when_its_handle_is_closed())
		return -1;
	if (!test_waiting_begin_proceeds_when_holder_is_closed())
		return -1;
	if (!test_reference_outlives_close())
		return -1;

	return 0;
}
