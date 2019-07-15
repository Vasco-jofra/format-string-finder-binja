import os
import subprocess

from binaryninja import log_debug, log_error, log_info, log_warn
from binaryninja import BinaryView, SymbolType, SymbolBinding, HighlightStandardColor
from binaryninja import MediumLevelILOperation as MLILOperation

from .mlil_var_analysis import MLILSSAVarAnalysisOrigins, VarOriginConst, VarOriginParameter, VarOriginCallResult

__all__ = ["FormatStringFinder"]


class PrintfLikeFunction:
    BASE_DIR = os.path.dirname(os.path.realpath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    USER_DATA_DIR = os.path.join(BASE_DIR, "data_user")

    def __init__(self, name, parameter_index):
        self.name = name
        self.parameter_index = parameter_index

    def __hash__(self):
        return hash((self.name, self.parameter_index))

    def __eq__(self, other):
        return self.name == other.name and self.parameter_index == other.parameter_index

    def __str__(self):
        return f"<PrintfLikeFunction( {self.name} , idx={self.parameter_index})>"

    @staticmethod
    def load_file(fpath):
        if not os.path.isfile(fpath):
            raise FileNotFoundError(f"Path {fpath} not found")

        res = []
        with open(fpath, "r") as f:
            for l in f:
                l = l.strip()
                if l == "" or l.startswith("#"):
                    continue
                name, param_idx = l.split(" ")
                res.append(PrintfLikeFunction(name.strip(), int(param_idx)))
        return res

    @staticmethod
    def load_all():
        """
        Load all printf like functions from the '/data' and '/data_user' dirs.
        """
        res = []
        dirs_to_load = [PrintfLikeFunction.DATA_DIR, PrintfLikeFunction.USER_DATA_DIR]

        for d in dirs_to_load:
            for fname in os.listdir(d):
                fpath = os.path.join(d, fname)
                res += PrintfLikeFunction.load_file(fpath)

        return res

    @staticmethod
    def save_to_user_data(fname, printf_like_funcs):
        fpath = os.path.join(PrintfLikeFunction.USER_DATA_DIR, fname)
        with open(fpath, "w") as f:
            for func in printf_like_funcs:
                f.write(f"{func.name} {func.parameter_index}\n")


class FormatStringFinderResult:
    def __init__(self, bv: BinaryView, ref):
        self.bv = bv
        self.ref = ref

        # If we never actually set the result because of some error
        self.failed = True

        # The result content
        self.is_vuln = None
        self.safe_origins = None
        self.vuln_origins = None

    def set_result(self, safe_origins, vuln_origins):
        self.failed = False

        self.safe_origins = safe_origins
        self.vuln_origins = vuln_origins
        self.is_vuln = (len(vuln_origins) != 0)

    def __str__(self):
        msg = f"{hex(self.ref.address)} : "

        if self.failed:
            msg += "failed analysis"
        else:
            if self.is_vuln:
                msg += "VULN "
                msg += str([str(i) for i in self.vuln_origins])
            else:
                msg += "SAFE "

                safe_origins_str = []
                for orig in self.safe_origins:
                    if isinstance(orig, VarOriginConst):
                        format_str = orig.get_string(self.bv)
                        if format_str is None:
                            format_str = str(orig)
                        else:
                            format_str = repr(format_str)

                        safe_origins_str.append(format_str)
                    else:
                        msg += str(orig)
                msg += ", ".join(safe_origins_str)

        return msg


class FormatStringFinder:
    def __init__(self, bv: BinaryView, should_highlight):
        self.bv = bv

        self.safe_functions = [
            "gettext",
            "dgettext",
            "dcgettext",
            "ngettext",
            "dngettext",
            "dcngettext",
        ]
        self.should_highlight = should_highlight

        self.results = []
        self.new_printf_like_funcs = set()
        self.heuristic_vul_function_ptr_calls = set()

    def find_format_strings(self, CHECK_WITH_READELF=False):
        visited = set()
        to_visit = []

        # ====================
        # Step 0: Get all hardcoded known printf_like functions
        to_visit = PrintfLikeFunction.load_all()
        # @@TODO: We could look for refs of strings with '%s', '%d'... and if they are the parameter of an external function, add those as 'printf like'

        while to_visit:
            printf_like_func = to_visit.pop(0)

            # Sometimes, due to saving printf_like_funcs in a file to later reload we get repeated entries
            if printf_like_func in visited:
                log_debug("Skipping analysis of duplicate printf_like_func ' %s '" % printf_like_func.name)
                continue
            visited.add(printf_like_func)

            syms = self.get_symbols_by_raw_name(printf_like_func.name)
            if not syms:
                if printf_like_func.name.startswith("sub_"):
                    log_error(f"No symbol found for function '{printf_like_func.name}'")
                continue

            log_debug(f"\n===== {printf_like_func} =====")
            log_debug(f" syms: {syms} =====")

            # @@TODO: Add arg name 'format' and type 'char*' to the format var (Tried before but arg and var get disconnected sometimes. Likely a bug.)

            # Get every ref for this symbol(s)
            refs = []
            for sym in syms:
                it_refs = self.bv.get_code_refs(sym.address)

                # readelf check to get a second opinion
                if CHECK_WITH_READELF and sym.type == SymbolType.ExternalSymbol:
                    self.check_relocations_with_readelf(sym, syms, it_refs)

                refs += it_refs

            # ====================
            # Step 1: Check each xref for vulns
            for ref in refs:
                log_debug(f"Analyzing xref {hex(ref.address)}")
                ref_result = FormatStringFinderResult(self.bv, ref)
                self.results.append(ref_result)

                # ====================
                # Step 1.0: Sanity checks
                mlil_instr = self.get_mlil_instr(ref.function, ref.address)
                if not mlil_instr:
                    continue

                # Check for known unhandled operations
                if mlil_instr.operation in (
                    MLILOperation.MLIL_CALL_UNTYPED, MLILOperation.MLIL_TAILCALL_UNTYPED
                ):
                    log_debug("@@TODO: How to handle MLIL_CALL_UNTYPED and MLIL_TAILCALL_UNTYPED?")
                    continue
                elif mlil_instr.operation in (MLILOperation.MLIL_SET_VAR, MLILOperation.MLIL_STORE):
                    # Our xref is being used to set a var and not in a call.
                    # @@TODO: Maybe we could try to find if it is called close by and use that as an xref
                    continue

                # If it wasn't one of the above, it must be one of these
                if mlil_instr.operation not in (MLILOperation.MLIL_CALL, MLILOperation.MLIL_TAILCALL):
                    assert False, f"mlil operation '{mlil_instr.operation.name}' is unsupported @ {hex(ref.address)}"

                # @@TODO: Can we force it to have the necessary arguments? Looking at the calling convention?
                if printf_like_func.parameter_index >= len(mlil_instr.params):
                    log_error(
                        f"{hex(ref.address)} : parameter nr {printf_like_func.parameter_index} for "
                        f"function call of '{printf_like_func.name}' is not available"
                    )
                    continue

                if self.should_highlight:
                    ref.function.set_user_instr_highlight(
                        ref.address, HighlightStandardColor.RedHighlightColor
                    )
                # ====================
                # Step 1.1: Find the origins of the format parameter for this xref
                fmt_param = mlil_instr.ssa_form.params[printf_like_func.parameter_index]

                if fmt_param.operation in (MLILOperation.MLIL_CONST, MLILOperation.MLIL_CONST_PTR):
                    # Handle immediate constants
                    var_origins = [VarOriginConst(fmt_param.constant)]
                elif fmt_param.operation in (MLILOperation.MLIL_VAR_SSA, MLILOperation.MLIL_VAR_ALIASED):
                    # @@TODO: What is the meaning of 'MLILOperation.MLIL_VAR_ALIASED' ?
                    # Find the origins of the variable
                    fmt_ssa = fmt_param.src
                    mlil_ssa = ref.function.medium_level_il.ssa_form

                    # Get the var origins. Can be a parameter, a const, an address of another var...
                    var_origins = MLILSSAVarAnalysisOrigins(self.bv,
                                                            mlil_ssa).run(fmt_ssa, self.should_highlight)
                else:
                    assert False, f"ERROR: fmt_param.operation is {fmt_param.operation.name} @ {hex(ref.address)}"

                if var_origins is None:
                    log_warn(f"{hex(ref.address)} : Failed to get origins of the format parameter")
                    continue

                # ====================
                # Step 1.2: Determine if the origins are safe or vulnerable
                # Case 1: If any origin is an argument -> PRINTF_LIKE
                # Case 2: If any is NOT a read-only constant or a parameter -> VULN
                # Case 3: If all are an arg or a const -> SAFE
                vuln_origins = []
                safe_origins = []

                for orig in var_origins:
                    if isinstance(orig, VarOriginParameter):
                        safe_origins.append(orig)

                        # Add as a printf like function
                        new_printf_like = PrintfLikeFunction(ref.function.name, orig.parameter_idx)  # pylint: disable=no-member
                        to_visit.append(new_printf_like)
                        self.new_printf_like_funcs.add(new_printf_like)

                        # Create a symbol for the new printf like function if it does not exist
                        if not self.bv.get_symbols_by_name(ref.function.name):
                            ref.function.name = ref.function.name

                    elif isinstance(orig, VarOriginConst) and self.is_addr_read_only(orig.const):
                        safe_origins.append(orig)

                    elif isinstance(orig, VarOriginCallResult) and orig.func_name in self.safe_functions:  # pylint: disable=no-member
                        # We accept that 'dcgettext' is safe because you need root to control the translation
                        safe_origins.append(orig)

                    else:
                        vuln_origins.append(orig)

                ref_result.set_result(safe_origins, vuln_origins)
                log_debug(str(ref_result))

                # ====================
                # Step 2: Heuristic to find function pointer calls that might me vulnerable
                self.heuristic_look_for_vul_function_ptr_calls(mlil_instr, var_origins)

        # ====================
        # Step 3: Save the exported functions to a file so other files that import them know they are printf like
        exported_printf_like_funcs = []
        for func in self.new_printf_like_funcs:
            syms = self.bv.get_symbols_by_name(func.name)
            if not syms:
                continue

            for s in syms:
                if s.type == SymbolType.FunctionSymbol and s.binding == SymbolBinding.GlobalBinding:
                    log_info(f"Saving exported function '{func.name}' to user_data")
                    exported_printf_like_funcs.append(func)
                    break

        if exported_printf_like_funcs:
            fname = os.path.basename(self.bv.file.filename)
            PrintfLikeFunction.save_to_user_data(fname, exported_printf_like_funcs)

    def heuristic_look_for_vul_function_ptr_calls(self, mlil_instr, var_origins):
        """
        Looks for things like:
        ```C
        printf("%s", input);
        this->debug_func(input);
        ```
        We don't know that `this->debug_func` receives a format string (and so our analysis fails) This simple heuristic finds these cases and we can then check by hand.
        """
        if len(var_origins) != 1:
            return

        orig = var_origins[0]
        if not isinstance(orig, VarOriginConst) or not self.is_addr_read_only(orig.const):
            return

        orig_str = orig.get_string(self.bv)
        if not orig_str:
            return

        # ====================
        # Restrict based on the string content
        if "%" not in orig_str:
            return

        # Ensure the string contains %s and that is no larger than 5 chars
        # This tries to include things like '%s\n' and '%s.\n'
        if len(orig_str) > 5 or "%s" not in orig_str:
            return

        # ====================
        # Look for calls using registers in the current and next few basic blocks
        # If we find one it might be a vulnerable call
        # @@TODO: We could check if the orig of one of its params is the same as the param after the fmt string in the original ref
        main_bb = mlil_instr.il_basic_block
        bbs_to_check = [main_bb] + [x.target for x in main_bb.outgoing_edges]

        for bb in bbs_to_check:
            for instr in bb:
                if instr.operation == MLILOperation.MLIL_CALL and instr.dest.operation == MLILOperation.MLIL_VAR:
                    log_debug(f"Heuristic finding {hex(instr.address)}")
                    self.heuristic_vul_function_ptr_calls.add(instr.address)

    def get_results_string(self):
        failed_results = [x for x in self.results if x.is_vuln is None]
        vuln_results = [x for x in self.results if x.is_vuln is True]
        safe_results = [x for x in self.results if x.is_vuln is False]

        md = ""
        md += f"# Format String Finder results for '{self.bv.file.filename}'\n"

        # Summary
        md += f" - Found {len(vuln_results)} vuln calls\n"
        md += f" - Found {len(safe_results)} safe calls\n"
        md += f" - Found {len(failed_results)} failed analysis\n"
        md += "\n"

        # Print the printf like functions we found
        md += "## Printf like functions\n"
        for i in self.new_printf_like_funcs:
            if i.name.startswith("sub_"):
                addr = int(i.name.replace("sub_", ""), 16)
            else:
                addr = self.bv.get_symbol_by_raw_name(i.name).address
            md += f" - {i.name} ( {hex(addr)} )\n"
        md += "\n"

        # Vulnerable results
        md += "## Vulnerable calls\n"
        for res in vuln_results:
            md += f" - {res}\n"
        md += "\n"

        # Heuristic findings
        if self.heuristic_vul_function_ptr_calls:
            md += "## Heuristic findings\n"
            for addr in self.heuristic_vul_function_ptr_calls:
                md += f" - {hex(addr)}\n"
            md += "\n"

        # Failed results
        if failed_results:
            md += "## Failed analysis\n"
            for res in failed_results:
                md += f" - {res}\n"
            md += "\n"

        # Safe results
        md += "## Safe calls\n"
        for res in safe_results:
            md += f" - {res}\n"
        md += "\n"

        # Then print every result per function analyzed
        return md

    # ====================
    # Helpers
    def is_addr_read_only(self, addr):
        return self.bv.is_offset_readable(addr) and not self.bv.is_offset_writable(addr)

    def get_symbols_by_raw_name(self, name):
        """
        API only has 'get_symbol_by_raw_name' and 'get_symbols_by_name'. The later demangles names (we don't want this here)
        """
        syms = self.bv.symbols.get(name)
        if not syms:  # pylint: disable=no-else-return
            return []
        elif not isinstance(syms, list):
            return [syms]
        else:
            return syms

    def get_mlil_instr(self, func, addr):
        llil_instr = func.get_low_level_il_at(addr)
        if not llil_instr:
            log_error(
                f"Couldn't get llil_instr at {hex(addr)}"
                f" (Could be because there are WRONG repeated xrefs for overlaping funcs)"
                f" (last time this happened it was (issue #1196) (should be fixed now)"
            )
            return None

        mlil_instr = llil_instr.medium_level_il
        if not mlil_instr:
            log_warn(f"Couldn't get mlil_instr from llil_instr at {hex(addr)} (probably was not a call)")
            return None

        return mlil_instr

    def check_relocations_with_readelf(self, syms, sym, refs):
        cmd = 'readelf -r "%s"  | grep -e " %s"' % (self.bv.file.filename, sym.name[:22])
        output = subprocess.check_output(cmd, shell=True).strip()
        readelf_reloc_addrs = {x.address for x in refs}
        for i in output.split("\n"):
            readelf_reloc_addrs.add(int(i.split(" ", 1)[0], 16) - 1)
        readelf_nr_relocs = len(readelf_reloc_addrs)

        # Ensure we only account once for each xref address (because of overlaping funcs)
        binja_reloc_addrs = {x.address for x in refs}
        binja_nr_relocs = len(binja_reloc_addrs)

        # Because there is a xref to the GOT which binja removes (I think)
        if len(syms) > 1:
            binja_nr_relocs += 1

        msg = "External symbol: relocs amount for '%s': Readelf=%-2d; Binja=%-2d" % (
            sym.name, readelf_nr_relocs, binja_nr_relocs
        )
        if readelf_nr_relocs != binja_nr_relocs:
            log_error(msg)
            log_error(
                "Different is: %s" %
                " ".join([hex(x) for x in readelf_reloc_addrs.difference(binja_reloc_addrs)])
            )

        if not (binja_nr_relocs <= readelf_nr_relocs):
            log_warn("Such ninja")