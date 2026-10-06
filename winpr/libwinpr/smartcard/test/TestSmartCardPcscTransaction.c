/**
 * Unit test for the PCSC transaction emulation in smartcard_pcsc_transaction.c
 *
 * Simulates pcsc-lite's per reader lock: a fake card handle encodes its reader
 * in the upper bits (hCard >> 8), the fake daemon tracks one lock owner per
 * reader and the fake clock advances only when the code under test sleeps.
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

static void fake_release_foreign(fake_pcsc* fake, size_t reader)
{
	if (fake->foreignReleaseAt && fake->now >= fake->foreignReleaseAt &&
	    fake->lockOwner[reader] == FOREIGN_HANDLE(reader))
		fake->lockOwner[reader] = 0;
}

static PCSC_LONG fake_begin(void* context, SCARDHANDLE hCard)
{
	fake_pcsc* fake = context;
	const size_t reader = FAKE_READER(hCard);
	fake->beginCalls++;
	fake->lastBegin = hCard;
	fake_release_foreign(fake, reader);
	if (fake->lockOwner[reader] != 0 && fake->lockOwner[reader] != hCard)
		return SCARD_E_SHARING_VIOLATION;
	fake->lockOwner[reader] = hCard;
	return SCARD_S_SUCCESS;
}

static PCSC_LONG fake_end(void* context, SCARDHANDLE hCard, PCSC_DWORD dwDisposition)
{
	fake_pcsc* fake = context;
	const size_t reader = FAKE_READER(hCard);
	fake->endCalls++;
	fake->lastEnd = hCard;
	fake->lastEndDisposition = dwDisposition;
	fake_release_foreign(fake, reader);
	/* pcscd: "No card reset within a transaction" of someone else */
	if (dwDisposition != SCARD_LEAVE_CARD && fake->lockOwner[reader] != 0 &&
	    fake->lockOwner[reader] != hCard)
		return SCARD_E_SHARING_VIOLATION;
	if (fake->lockOwner[reader] == hCard)
		fake->lockOwner[reader] = 0;
	return SCARD_S_SUCCESS;
}

static PCSC_LONG fake_probe(void* context, SCARDHANDLE hCard)
{
	fake_pcsc* fake = context;
	const size_t reader = FAKE_READER(hCard);
	fake->probeCalls++;
	fake_release_foreign(fake, reader);
	if (fake->lockOwner[reader] != 0 && fake->lockOwner[reader] != hCard)
		return SCARD_E_SHARING_VIOLATION;
	return SCARD_S_SUCCESS;
}

static void fake_sleep(void* context, UINT32 ms)
{
	fake_pcsc* fake = context;
	fake->sleepCalls++;
	fake->now += ms;
}

static UINT64 fake_tick(void* context)
{
	fake_pcsc* fake = context;
	return fake->now;
}

typedef struct
{
	fake_pcsc fake;
	PCSC_TRANSACTION_OPS ops;
	PCSC_TRANSACTION_TABLE* table;
} fixture;

static BOOL fixture_init(fixture* f)
{
	memset(f, 0, sizeof(*f));
	f->ops.context = &f->fake;
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
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));

	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);

	CHECK(f.fake.beginCalls == 0);
	CHECK(f.fake.probeCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_io_outside_transaction_does_not_lock(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));

	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);

	CHECK(f.fake.beginCalls == 0);
	CHECK(f.fake.probeCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_first_io_in_transaction_takes_lock_once(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));
	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);

	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);
	CHECK(f.fake.lastBegin == 0x101);
	CHECK(f.fake.lockOwner[1] == 0x101);

	/* further I/O in the same transaction reuses the lock */
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);
	CHECK(f.fake.sleepCalls == 0);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_end_releases_lock_with_disposition(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));
	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);

	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_RESET_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_RESET_CARD);
	CHECK(f.fake.lockOwner[1] == 0);

	/* I/O after the transaction is plain shared access again */
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_unbalanced_end_is_rejected(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));

	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_LEAVE_CARD) == SCARD_E_NOT_TRANSACTED);
	CHECK(f.fake.endCalls == 0);

	/* the handle is still usable afterwards */
	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.beginCalls == 1);
	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_our_handles_hand_over_lock_without_waiting(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	PCSC_TRANSACTION_HANDLE b;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));
	CHECK(PCSC_TransactionHandleInit(&b, 0x102, "Reader 1"));

	/* both handles are inside a transaction, A does I/O first */
	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionBegin(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);

	/* B's I/O takes the lock away from A: pcsc-lite End(A), Begin(B) */
	CHECK(PCSC_TransactionAcquire(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_LEAVE_CARD);
	CHECK(f.fake.beginCalls == 2);
	CHECK(f.fake.sleepCalls == 0);

	/* A's next I/O takes it back, still without waiting */
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(f.fake.endCalls == 2);
	CHECK(f.fake.lastEnd == 0x102);
	CHECK(f.fake.beginCalls == 3);
	CHECK(f.fake.sleepCalls == 0);

	/* B ends its transaction while A holds the lock: nothing to release */
	CHECK(PCSC_TransactionEnd(f.table, &b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 2);
	CHECK(f.fake.lockOwner[1] == 0x101);

	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 3);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleUninit(f.table, &a);
	PCSC_TransactionHandleUninit(f.table, &b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_different_readers_lock_independently(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	PCSC_TRANSACTION_HANDLE b;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));
	CHECK(PCSC_TransactionHandleInit(&b, 0x201, "Reader 2"));

	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionBegin(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &b) == SCARD_S_SUCCESS);

	/* both locks are held at the same time, nothing was handed over */
	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(f.fake.lockOwner[2] == 0x201);
	CHECK(f.fake.beginCalls == 2);
	CHECK(f.fake.endCalls == 0);

	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0);
	CHECK(f.fake.lockOwner[2] == 0x201);
	CHECK(PCSC_TransactionEnd(f.table, &b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[2] == 0);

	PCSC_TransactionHandleUninit(f.table, &a);
	PCSC_TransactionHandleUninit(f.table, &b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_waits_for_foreign_holder_to_release(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));

	/* some other application holds the reader lock for 300ms */
	f.fake.lockOwner[1] = FOREIGN_HANDLE(1);
	f.fake.foreignReleaseAt = 300;

	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);

	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(f.fake.sleepCalls == 3);
	CHECK(f.fake.now == 300);
	/* the blocking pcsc-lite call is only made once the lock is free */
	CHECK(f.fake.beginCalls == 1);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_gives_up_on_foreign_holder_after_timeout(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));

	/* some other application holds the reader lock and never lets go */
	f.fake.lockOwner[1] = FOREIGN_HANDLE(1);
	f.fake.foreignReleaseAt = 0;

	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_E_SHARING_VIOLATION);

	CHECK(f.fake.now == PCSC_TRANSACTION_WAIT_MS);
	CHECK(f.fake.sleepCalls == PCSC_TRANSACTION_WAIT_MS / PCSC_TRANSACTION_POLL_MS);
	CHECK(f.fake.beginCalls == 0);
	CHECK(f.fake.lockOwner[1] == FOREIGN_HANDLE(1));

	/* the transaction is still open; once the holder is gone I/O works */
	f.fake.lockOwner[1] = 0;
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);
	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_end_with_reset_forwards_even_without_lock(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	PCSC_TRANSACTION_HANDLE b;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));
	CHECK(PCSC_TransactionHandleInit(&b, 0x102, "Reader 1"));

	/* A never did any I/O, so it holds no lock, but asks for a reset */
	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_RESET_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_RESET_CARD);

	/* B holds the lock when A asks for a reset: B's lock is given up first,
	 * pcscd refuses a reset while another handle holds the lock */
	CHECK(PCSC_TransactionBegin(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_UNPOWER_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 3);
	CHECK(f.fake.lastEnd == 0x101);
	CHECK(f.fake.lastEndDisposition == SCARD_UNPOWER_CARD);
	CHECK(f.fake.lockOwner[1] == 0);

	/* B's transaction is still open, its next I/O takes the lock again */
	CHECK(PCSC_TransactionAcquire(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(PCSC_TransactionEnd(f.table, &b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleUninit(f.table, &a);
	PCSC_TransactionHandleUninit(f.table, &b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_disconnect_drops_lock_ownership(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	PCSC_TRANSACTION_HANDLE b;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));
	CHECK(PCSC_TransactionHandleInit(&b, 0x102, "Reader 1"));

	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);

	/* SCardDisconnect while in a transaction: pcscd released the lock itself */
	PCSC_TransactionHandleUninit(f.table, &a);
	f.fake.lockOwner[1] = 0;
	CHECK(f.fake.endCalls == 0);

	/* B must not try to hand over from the dead handle */
	CHECK(PCSC_TransactionBegin(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &b) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0x102);
	CHECK(PCSC_TransactionEnd(f.table, &b, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);

	PCSC_TransactionHandleUninit(f.table, &b);
	fixture_uninit(&f);
	return TRUE;
}

static BOOL test_nested_transaction_releases_on_outermost_end(void)
{
	fixture f;
	PCSC_TRANSACTION_HANDLE a;
	CHECK(fixture_init(&f));
	CHECK(PCSC_TransactionHandleInit(&a, 0x101, "Reader 1"));

	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionBegin(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(PCSC_TransactionAcquire(f.table, &a) == SCARD_S_SUCCESS);
	CHECK(f.fake.lockOwner[1] == 0x101);

	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 0);
	CHECK(f.fake.lockOwner[1] == 0x101);

	CHECK(PCSC_TransactionEnd(f.table, &a, SCARD_LEAVE_CARD) == SCARD_S_SUCCESS);
	CHECK(f.fake.endCalls == 1);
	CHECK(f.fake.lockOwner[1] == 0);

	PCSC_TransactionHandleUninit(f.table, &a);
	fixture_uninit(&f);
	return TRUE;
}

int TestSmartCardPcscTransaction(int argc, char* argv[])
{
	WINPR_UNUSED(argc);
	WINPR_UNUSED(argv);

	if (!test_nested_transaction_releases_on_outermost_end())
		return -1;
	if (!test_end_with_reset_forwards_even_without_lock())
		return -1;
	if (!test_disconnect_drops_lock_ownership())
		return -1;

	if (!test_our_handles_hand_over_lock_without_waiting())
		return -1;
	if (!test_different_readers_lock_independently())
		return -1;
	if (!test_waits_for_foreign_holder_to_release())
		return -1;
	if (!test_gives_up_on_foreign_holder_after_timeout())
		return -1;

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

	return 0;
}
