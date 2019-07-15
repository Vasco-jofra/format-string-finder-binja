from binaryninja import log_info, log_warn, log_error
from binaryninja import MediumLevelILFunction, MediumLevelILInstruction, SSAVariable, HighlightStandardColor, BinaryView
from binaryninja import MediumLevelILOperation as MLILOperation

__all__ = [
    "MLILSSAVarAnalysisOrigins", "VarOriginParameter", "VarOriginConst", "VarOriginAddressOf",
    "VarOriginCallResult", "VarOriginUnknown", "VarOriginLoad"
]


class VarOriginParameter:
    def __init__(self, parameter_idx):
        self.parameter_idx = parameter_idx

    def __str__(self):
        return f"<VarOriginParameter(idx={self.parameter_idx})>"


class VarOriginConst:
    def __init__(self, const):
        self.const = const

    def get_string(self, bv: BinaryView):
        s = bv.get_string_at(self.const, partial=True)

        if s:
            s = s.value
        else:
            # Get string with size of 3 or less (get_string_at does not return these)
            s = str(bv.read(self.const, 4))
            if "\x00" not in s:
                s = None
            else:
                s = s.split("\x00", 1)[0]
                s = str(s)

        return s

    def __str__(self):
        return f"<VarOriginConst(const={hex(self.const)})>"


class VarOriginAddressOf:
    def __init__(self, var):
        self.var = var

    def __str__(self):
        return f"<VarOriginAddressOf({self.var})>"


class VarOriginLoad:
    def __str__(self):
        return f"<VarOriginLoad()>"


class VarOriginCallResult:
    def __init__(self, func_name):
        self.func_name = func_name

    def __str__(self):
        return f"<VarOriginCallResult(func={self.func_name})>"


class VarOriginUnknown:
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return f"<VarOriginUnknown(\"{self.msg}\")>"


class MLILSSAVarAnalysisOrigins:
    def __init__(self, bv: BinaryView, mlil_ssa_func: MediumLevelILFunction):
        self.bv = bv
        self.mlil_ssa_func = mlil_ssa_func

        self.func = mlil_ssa_func.source_function

    def run(self, ssa_var: SSAVariable, should_highlight, visited=None):
        origins = []
        if visited is None:
            visited = set()

        while True:
            if ssa_var in visited:
                # Seen a case where we had (in '/bin/dash'):
                #   - r13_1#4 = ϕ(r13_1#3, r13_1#6)
                #   - r13_1#6 = ϕ(r13_1#4, r13_1#5)
                msg = f"Found phi vars (including {ssa_var}) that depend on each other in function {ssa_var.var.function.start}. I've only seen this happen a couple of times."
                log_error(msg)
                origins.append(VarOriginUnknown(msg))
                return origins
            visited.add(ssa_var)

            # Step 1: If we reach an ssa_var with version 0, it will have no more definitions
            if ssa_var.version == 0:
                is_parameter, parameter_idx = self.is_ssa_var_a_parameter(ssa_var)
                if is_parameter:
                    origins.append(VarOriginParameter(parameter_idx))
                else:
                    # Var is version 0 but not a function parameter. Sometimes these are stack addrs.
                    origins.append(VarOriginUnknown("Var is version 0 but not a function parameter"))
                return origins

            # Step 2: Get the next definition
            var_def_instr: MediumLevelILInstruction = self.mlil_ssa_func.get_ssa_var_definition(ssa_var)
            if var_def_instr is None:
                msg = f"{ssa_var} has no definition in function {hex(ssa_var.var.function.start)} (Not sure how this is possible)"
                log_error(msg)
                origins.append(VarOriginUnknown(msg))
                return origins

            if should_highlight:
                self.func.set_user_instr_highlight(
                    var_def_instr.address, HighlightStandardColor.OrangeHighlightColor
                )

            # log_info(str(var_def_instr.operation) + ": " + str(var_def_instr))

            # Step 3: Get the next var/vars to check
            if var_def_instr.operation in (
                MLILOperation.MLIL_SET_VAR_SSA, MLILOperation.MLIL_SET_VAR_ALIASED
            ):
                src = var_def_instr.src
                if src.operation == MLILOperation.MLIL_VAR_SSA:
                    # Keep propagating backwards
                    ssa_var = src.src
                    continue

                if src.operation in (MLILOperation.MLIL_CONST, MLILOperation.MLIL_CONST_PTR):
                    # Found a constant
                    origins.append(VarOriginConst(src.constant))
                elif src.operation == MLILOperation.MLIL_ADDRESS_OF:
                    origins.append(VarOriginAddressOf(src.src))
                elif src.operation == MLILOperation.MLIL_LOAD_SSA:
                    origins.append(VarOriginLoad())
                else:
                    # We are NOT interested in things like adds/subs because we are looking for either arguments or constants
                    msg = f"{src.operation.name} for a MLIL_SET_VAR_SSA src, so we stopped propagating the chain."
                    origins.append(VarOriginUnknown(msg))
                    log_warn(msg)

            elif var_def_instr.operation == MLILOperation.MLIL_VAR_PHI:
                # Find the origins of each PHI
                for phi_var in var_def_instr.src:
                    origins += self.run(phi_var, should_highlight=should_highlight, visited=visited)

            elif var_def_instr.operation == MLILOperation.MLIL_CALL_SSA:
                # Found a var defined as the result of a function call
                func_addr = var_def_instr.dest.value.value
                func = self.bv.get_function_at(func_addr)
                if func is None:
                    # A function call from an address that has no function?
                    msg = f"Couldn't get function at {hex(func_addr)} (from MLIL_CALL_SSA at {var_def_instr.address})."
                    origins.append(VarOriginUnknown(msg))
                    log_error(msg)
                else:
                    func_name = self.bv.get_function_at(var_def_instr.dest.value.value).name
                    origins.append(VarOriginCallResult(func_name))

            else:
                # What is this??
                msg = f"{var_def_instr.operation.name} not supported at {hex(var_def_instr.address)}"
                origins.append(VarOriginUnknown(msg))
                log_error(msg)

            return origins

    # ====================
    def is_var_a_parameter(self, var):
        for i, it in enumerate(self.func.parameter_vars):
            if var == it:
                return True, i
        return False, None

    def is_ssa_var_a_parameter(self, ssa_var):
        return self.is_var_a_parameter(ssa_var.var)


# For testing
if __name__ == "__console__":
    log_info("\n====================\nOrigins")
    analysis = MLILSSAVarAnalysisOrigins(bv, current_mlil.ssa_form)  # pylint: disable=undefined-variable
    origs = analysis.run(current_mlil.ssa_form[26].operands[2][0].src, True)  # pylint: disable=undefined-variable
    log_info(str([str(i) for i in origs]))