import os

from binaryninja import BinaryViewType, log_info, log_error

from ..src import FormatStringFinder

__all__ = ["run_fs_tests"]


def run_fs_test(fpath):
    bv = BinaryViewType.get_view_of_file(fpath)
    bv.update_analysis_and_wait()

    fs_finder = FormatStringFinder(bv, False)
    fs_finder.find_format_strings()

    # ====================
    # Prepare what should be found
    success = True
    printf_like_funcs = [x for x in bv.symbols if x.startswith("PRINTF_LIKE")]
    vuln_funcs = [x for x in bv.symbols if x.startswith("VULN")]
    safe_funcs = [x for x in bv.symbols if x.startswith("SAFE")]

    def test_helper(should_be_found, found, msg_type):
        nonlocal success

        for i in should_be_found:
            if i not in found:
                log_error(f"'{i}' was not detected as a {msg_type}.")
                success = False
            else:
                log_info(f"'{i}' successfully detected as a {msg_type}.")

    # ====================
    # Check that every printf like function was found
    found_printf_like_funcs = [x.name for x in fs_finder.new_printf_like_funcs]
    test_helper(printf_like_funcs, found_printf_like_funcs, "printf like function")

    # ====================
    # Check that all safe/vuln results are in safe/vuln functions
    found_vuln_funcs = [x.ref.function.name for x in fs_finder.results if x.is_vuln]
    found_safe_funcs = [x.ref.function.name for x in fs_finder.results if not x.is_vuln]
    test_helper(vuln_funcs, found_vuln_funcs, "vuln function")
    test_helper(safe_funcs, found_safe_funcs, "safe function")

    bv.file.close()
    return success


def run_fs_tests(_=None):
    bins_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "data")

    all_tests_succeeded = True
    for fname in os.listdir(bins_dir):
        if not fname.endswith(".bin"):
            continue

        fpath = os.path.join(bins_dir, fname)
        log_info("\n" + "=" * 40)
        log_info("Running test on binary %s" % (fpath))

        success = run_fs_test(fpath)
        if success:
            log_info(f"Test passed!")
        else:
            all_tests_succeeded = False
            log_error(f"Test failed!")

    if all_tests_succeeded:
        log_info(f"All tests passed!")
    else:
        log_error(f"Some tests failed!")
