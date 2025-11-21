"""
gdb python script for dumping the BEAM offsets.
"""

def no_member_to_none(fn):
    """Decorator translating errors about missing field to `None`."""
    def wrap(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except gdb.error as e:
            if 'no member named' in str(e):
                return None
            raise
    return wrap

@no_member_to_none
def offset_of(ty, field):
    return int(gdb.parse_and_eval(f'(uintptr_t)(&(({ty}*)0)->{field})'))

@no_member_to_none
def size_of(ty):
    return int(gdb.parse_and_eval(f'sizeof({ty})'))

@no_member_to_none
def size_of_field(ty, field):
    return int(gdb.parse_and_eval(f'sizeof((({ty}*)0)->{field})'))


fields = {
    'ranges.size_of': size_of('struct ranges'),
    'ranges.modules': offset_of('struct ranges', 'modules'),
    'ranges.n': offset_of('struct ranges', 'n'),
    
    'ranges_entry.size_of': size_of('Range'),
    'ranges_entry.start': offset_of('Range', 'start'),
    'ranges_entry.end': offset_of('Range', 'end'),

    'beam_code_header.size_of': size_of('beam_code_header'),
    'beam_code_header.num_functions': offset_of('beam_code_header', 'num_functions'),
    'beam_code_header.line_table': offset_of('beam_code_header', 'line_table'),
    'beam_code_header.functions': offset_of('beam_code_header', 'functions'),

    'erts_code_info.size_of': size_of('ErtsCodeInfo'),
    'erts_code_info.mfa': offset_of('ErtsCodeInfo', 'mfa'),

    'erts_code_mfa.module': offset_of('ErtsCodeMFA', 'module'),
    'erts_code_mfa.function': offset_of('ErtsCodeMFA', 'function'),
    'erts_code_mfa.arity': offset_of('ErtsCodeMFA', 'arity'),

    'beam_code_line_tab.size_of': size_of('BeamCodeLineTab'),
    'beam_code_line_tab.fname_ptr': offset_of('BeamCodeLineTab', 'fname_ptr'),
    'beam_code_line_tab.loc_size': offset_of('BeamCodeLineTab', 'loc_size'),
    'beam_code_line_tab.loc_tab': offset_of('BeamCodeLineTab', 'loc_tab'),
    'beam_code_line_tab.func_tab': offset_of('BeamCodeLineTab', 'func_tab'),

    'index_table.seg_table': offset_of('IndexTable', 'seg_table'),

    'atom.len': offset_of('Atom', 'len'),
    'atom.name': offset_of('Atom', 'name'),
    'atom.u.bin': offset_of('Atom', 'u.bin'),
    
    'erl_heap_bits.data': offset_of('ErlHeapBits', 'data'),
}


for field, value in fields.items():
    if value is None:
        print(f"vms.{field}: <field not present>")
    else:
        print(f"vms.{field}={value}")
