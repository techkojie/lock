import keyring
from src.auth.auth import (
    set_master_password,
    verify_master_password,
    is_password_set,
    clear_master_password,
    recover_with_key
)

def test_persistence():
    print()
    print("=== PERSISTENCE STRESS TEST ===")

    # ── Step 1: Clean start ──────────────────────────────
    print()
    print("Step 1: Clearing any existing credentials...")
    clear_master_password()
    assert not is_password_set(), "FAIL: credentials not cleared"
    print("PASS: Clean slate confirmed")

    # ── Step 2: Set password ─────────────────────────────
    print()
    print("Step 2: Setting master password...")
    TEST_PASSWORD = "StressTest@2026!"
    recovery_key = set_master_password(TEST_PASSWORD)
    assert is_password_set(), "FAIL: password not stored"
    assert len(recovery_key) == 24, "FAIL: recovery key wrong length"
    assert recovery_key.count("-") == 4, "FAIL: recovery key wrong format"
    print("PASS: Password set and stored")
    print("PASS: Recovery key format correct:", recovery_key)

    # ── Step 3: Verify immediately ───────────────────────
    print()
    print("Step 3: Verifying immediately after set...")
    assert verify_master_password(TEST_PASSWORD), \
        "FAIL: immediate verify failed"
    assert not verify_master_password("WrongPassword!"), \
        "FAIL: wrong password accepted"
    assert not verify_master_password(""), \
        "FAIL: empty password accepted"
    print("PASS: Immediate verification works")

    # ── Step 4: Simulate session close and reopen ────────
    print()
    print("Step 4: Simulating session close and reopen...")
    stored = keyring.get_password(
        "FolderLocker", "master_password_hash"
    )
    assert stored is not None, "FAIL: nothing in keyring"
    assert stored.startswith("600000"), \
        "FAIL: wrong hash format in keyring"
    parts = stored.split("$")
    assert len(parts) == 3, \
        "FAIL: stored hash has wrong structure"
    print("PASS: Hash correctly stored in keyring")
    print(
        "PASS: Format confirmed —",
        parts[0],
        "/ salt len:", len(parts[1]),
        "/ key len:", len(parts[2])
    )

    # ── Step 5: Verify after simulated session ───────────
    print()
    print("Step 5: Verifying after simulated session reopen...")
    assert verify_master_password(TEST_PASSWORD), \
        "FAIL: post session verify failed"
    print("PASS: Password survives simulated session")

    # ── Step 6: Wrong passwords rejected ─────────────────
    print()
    print("Step 6: Confirming wrong passwords rejected...")
    wrong_passwords = [
        "wrongpassword",
        "StressTest@2026",
        "stresstest@2026!",
        "STRESSTEST@2026!",
        " ",
        "StressTest@2026! ",
    ]
    for wrong in wrong_passwords:
        result = verify_master_password(wrong)
        assert not result, f"FAIL: wrong password accepted: {wrong}"
    print("PASS: All wrong passwords rejected")

    # ── Step 7: Recovery key resets password ─────────────
    print()
    print("Step 7: Testing recovery key reset...")
    new_recovery = recover_with_key(
        recovery_key,
        "NewPassword@2026!"
    )
    assert verify_master_password("NewPassword@2026!"), \
        "FAIL: new password not working after recovery"
    assert not verify_master_password(TEST_PASSWORD), \
        "FAIL: old password still works after recovery"
    assert isinstance(new_recovery, str), \
        "FAIL: no new recovery key returned"
    assert len(new_recovery) == 24, \
        "FAIL: new recovery key wrong length"
    assert new_recovery.count("-") == 4, \
        "FAIL: new recovery key wrong format"
    print("PASS: Recovery key resets password correctly")
    print("PASS: Old password rejected after reset")
    print("PASS: New recovery key generated:", new_recovery)

    # ── Step 8: Old recovery key is dead ─────────────────
    print()
    print("Step 8: Confirming old recovery key invalidated...")
    try:
        recover_with_key(recovery_key, "AnotherPassword@2026!")
        assert False, "FAIL: old recovery key still works"
    except ValueError:
        print("PASS: Old recovery key correctly rejected")

    # ── Step 9: Final state ───────────────────────────────
    print()
    print("Step 9: Final state verification...")
    assert is_password_set(), "FAIL: password not set at end"
    final_stored = keyring.get_password(
        "FolderLocker", "master_password_hash"
    )
    assert final_stored is not None, \
        "FAIL: nothing in keyring at end"
    assert final_stored.startswith("600000"), \
        "FAIL: wrong format at end"
    print("PASS: Final state is clean and correct")

    # ── Step 10: Cleanup ──────────────────────────────────
    print()
    print("Step 10: Cleaning up test credentials...")
    clear_master_password()
    assert not is_password_set(), "FAIL: cleanup failed"
    print("PASS: Cleanup complete")

    print()
    print("=" * 45)
    print("ALL PERSISTENCE STRESS TESTS PASSED")
    print("=" * 45)