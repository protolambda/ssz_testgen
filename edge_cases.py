from inspect import getmembers, isclass

from typing import Dict, Set, Callable, Type, Tuple, List as PyList, Protocol
from random import Random
from zlib import adler32

from eth2spec.phase0 import spec

from remerkleable.complex import Container, Vector, List
from remerkleable.basic import boolean, bit, uint, byte, uint8, uint16, uint32, uint64, uint128, uint256
from remerkleable.bitfields import Bitvector, Bitlist
from remerkleable.byte_arrays import ByteVector, Bytes1, Bytes4, Bytes8, Bytes32, Bytes48, Bytes96, ByteList
from remerkleable.core import BasicView, View, TypeDef, OFFSET_BYTE_LENGTH


def str_hash(v: str) -> int:
    return adler32(v.encode('utf-8'))


def get_spec_ssz_types():
    return [
        (name, value) for (name, value) in getmembers(spec, isclass)
        if issubclass(value, Container) and value != Container  # only the subclasses, not the imported base class
    ]

EdgeCaseEncoder = Callable[["Proxy", Type[View], Random, "EdgeCaseEncoder"], bytes]

Annotation = PyList[str]

class Annotator(object):
    here: Annotation
    dest: Callable[[Annotation], None]

    def __init__(self, here: Annotation, dest: Callable[[Annotation], None]):
        self.here = here
        self.dest = dest

    # def __call__(self, wrapped_ee: EdgeCaseEncoder) -> EdgeCaseEncoder:
    #     def wrap(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    #         return wrapped_ee(ann, typ, rng, ee)
    #     return wrap

    def annotate(self, v: str) -> "Annotator":
        return Annotator(self.here + [v], self.dest)

    def report(self):
        self.dest(self.here)


EdgeCaseApplicableFn = Callable[[Type[View]], bool]
EdgeCaseTag = str
edge_cases_encoders: Dict[EdgeCaseTag, PyList[Tuple[EdgeCaseApplicableFn, EdgeCaseEncoder]]] = dict()
all_encoders: PyList[Tuple[EdgeCaseApplicableFn, EdgeCaseEncoder]] = list()



# Decorator to register an edge case encoder with
def edge_case(applicable_fn: EdgeCaseApplicableFn, tags: Set[str]) -> Callable[[EdgeCaseEncoder], EdgeCaseEncoder]:
    def wrap(fn: EdgeCaseEncoder):
        def entry(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:
            ann = ann.annotate(fn.__name__)
            ann.report()
            return fn(ann, typ, rng, ee)
        for tag in tags:
            if tag not in edge_cases_encoders:
                edge_cases_encoders[tag] = list()
            tag_encs = edge_cases_encoders[tag]
            tag_encs.append((applicable_fn, entry))
        all_encoders.append((applicable_fn, entry))
        return entry
    return wrap


def type_edge_case(typ: Type[View], tags: Set[str]) -> Callable[[Callable], EdgeCaseEncoder]:
    def check(t) -> bool:
        return issubclass(t, typ)
    return edge_case(check, tags)


def general_edge_case(tags: Set[str]):
    return edge_case(applicable_fn=lambda t: True, tags=tags)


def fixedlen_or_offsetlen(x: Type[View]) -> int:
    return x.type_byte_length() if x.is_fixed_byte_length() else OFFSET_BYTE_LENGTH


def encode_offset(offset: int) -> bytes:
    return uint32(offset).encode_bytes()


########################################################################################################################


@general_edge_case({'default'})
def default_value(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    default_value = typ.default(hook=None)  # Fully zeroed/empty everything (except necessary offsets etc.)
    return default_value.encode_bytes()


########################################################################################################################


@type_edge_case(ByteList, {'random'})
def random_byte_list(ann: Annotator, typ: Type[ByteList], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(ByteList, {'min', 'zero'})
def zero_byte_list(ann: Annotator, typ: Type[ByteList], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(ByteList, {'max'})
def max_byte_list(ann: Annotator, typ: Type[ByteList], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(ByteList, {'full'})
def full_byte_list(ann: Annotator, typ: Type[ByteList], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(ByteList, {'empty'})
def empty_byte_list(ann: Annotator, typ: Type[ByteList], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO


########################################################################################################################


@type_edge_case(ByteVector, {'random'})
def random_byte_vector(ann: Annotator, typ: Type[ByteVector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(ByteVector, {'min', 'zero'})
def zero_byte_vector(ann: Annotator, typ: Type[ByteVector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(ByteVector, {'max'})
def max_byte_vector(ann: Annotator, typ: Type[ByteVector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO


########################################################################################################################


@type_edge_case(boolean, {'random'})
def random_boolean(ann: Annotator, typ: Type[boolean], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    if rng.choice((True, False)):
        return b"\x01"
    else:
        return b"\x00"

@type_edge_case(boolean, {'min', 'zero'})
def false_boolean(ann: Annotator, typ: Type[boolean], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return b"\x00"

@type_edge_case(boolean, {'max', 'one'})
def true_boolean(ann: Annotator, typ: Type[boolean], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return b"\x01"

@type_edge_case(boolean, {'abs_max'})
def abs_max_boolean(ann: Annotator, typ: Type[boolean], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return b"\xff"

@type_edge_case(boolean, {'any_random'})
def any_byte_boolean(ann: Annotator, typ: Type[boolean], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return rng.randrange(0, 256).to_bytes(length=1, byteorder='little')


########################################################################################################################


@type_edge_case(uint, {'random'})
def random_uint(ann: Annotator, typ: Type[uint], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return rng.randrange(0, 256**(typ.type_byte_length())).to_bytes(length=typ.type_byte_length(), byteorder='little')

@type_edge_case(uint, {'min', 'zero'})
def zero_uint(ann: Annotator, typ: Type[uint], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return b"\x00" * typ.type_byte_length()

@type_edge_case(uint, {'one'})
def one_uint(ann: Annotator, typ: Type[uint], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return (1).to_bytes(length=typ.type_byte_length(), byteorder='little')

@type_edge_case(uint, {'max', 'abs_max'})
def max_uint(ann: Annotator, typ: Type[uint], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    return b"\xff" * typ.type_byte_length()

@type_edge_case(uint, {'endian'})
def wrong_endian_uint(ann: Annotator, typ: Type[uint], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    # Bias bytes towards wrong half of the uint bytes, for lots of starting zeroes and high set bits.
    return rng.randrange(0, 2**(8*typ.type_byte_length()//2)).to_bytes(length=typ.type_byte_length(), byteorder='big')


# TODO: extra 0 padding bytes


########################################################################################################################


@type_edge_case(Bitlist, {'random'})
def random_bitlist(ann: Annotator, typ: Type[Bitlist], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Bitlist, {'min', 'zero'})
def zero_bitlist(ann: Annotator, typ: Type[Bitlist], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Bitlist, {'max'})
def max_bitlist(ann: Annotator, typ: Type[Bitlist], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Bitlist, {'full'})
def full_bitlist(ann: Annotator, typ: Type[Bitlist], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Bitlist, {'empty'})
def empty_bitlist(ann: Annotator, typ: Type[Bitlist], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO


@type_edge_case(Bitlist, {'limit'})
def bitlist_exceed_limit_closely(ann: Annotator, typ: Type[Bitlist], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    limit = typ.limit()
    # Excludes the last byte that has the delimit bit.
    # bitlimit(3) -> 0 bytes
    # bitlimit(7) -> 0 bytes (delimit bit is last bit in first byte)
    # bitlimit(8) -> 1 byte (delimit bit is in second byte)
    # bitlimit(9) -> 1 byte (delimit bit is in second byte still)
    start_byte_len = limit // 8
    start_bytes = ee(ann, ByteVector[start_byte_len], rng, ee)
    min_bad_delimit_bit_pos = (limit % 8) + 1
    last_byte = (1 << rng.randrange(min_bad_delimit_bit_pos, 8)).to_bytes(length=1, byteorder='little')
    return start_bytes + last_byte


# TODO: exceed bitlist length in byte count


########################################################################################################################


@type_edge_case(Bitvector, {'random'})
def random_bitvector(ann: Annotator, typ: Type[Bitvector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Bitvector, {'min', 'zero'})
def zero_bitvector(ann: Annotator, typ: Type[Bitvector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Bitvector, {'max'})
def max_bitvector(ann: Annotator, typ: Type[Bitvector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

# TODO: exceed bitvector length

########################################################################################################################



@type_edge_case(List, {'random'})
def random_list(ann: Annotator, typ: Type[List], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(List, {'min', 'zero'})
def zero_list(ann: Annotator, typ: Type[List], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(List, {'max'})
def max_list(ann: Annotator, typ: Type[List], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(List, {'full'})
def full_list(ann: Annotator, typ: Type[List], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(List, {'empty'})
def empty_list(ann: Annotator, typ: Type[List], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO


# TODO: exceed list length


########################################################################################################################


@type_edge_case(Vector, {'random'})
def random_vector(ann: Annotator, typ: Type[Vector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Vector, {'min', 'zero'})
def zero_vector(ann: Annotator, typ: Type[Vector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO

@type_edge_case(Vector, {'max'})
def max_vector(ann: Annotator, typ: Type[Vector], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO


# TODO: exceed vector length


########################################################################################################################


@type_edge_case(Container, {'random'})
def random_container(ann: Annotator, typ: Type[Container], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    length = 0
    return b""  # TODO


@type_edge_case(Container, {'offsets', 'scramble'})
def scrambled_var_fields(ann: Annotator, typ: Type[Container], rng: Random, ee: EdgeCaseEncoder) -> bytes:
    fields = typ.fields()
    fields_data = [ee(ann.annotate(f_name), f_typ, rng, ee) for f_name, f_typ in fields.items()]
    dyn_field_indices = [i for i, f_typ in enumerate(fields.values()) if not f_typ.is_fixed_byte_length()]
    rng.shuffle(dyn_field_indices)
    dyn_field_datas = [fields_data[i] for i in dyn_field_indices]
    out = b""

    # Start off after the fixed bytes part
    offset = sum(map(fixedlen_or_offsetlen, fields.values()))
    dyn_i = 0
    for i in range(len(fields_data)):
        if i in dyn_field_indices:
            out += encode_offset(offset)
            offset += len(dyn_field_datas[dyn_i])
            dyn_i += 1
        else:
            out += fields_data[i]
    out += b"".join(dyn_field_datas)
    return out


def build_edge_cases(typ: Type[View], random_count: int):

    def random_any_ee(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:
        selected_ee = rng.choice([enc for (appl, enc) in all_encoders if appl(typ)])
        return selected_ee(ann, typ, rng, random_any_ee)

    def random_with_any_of_tags(tags: Set[EdgeCaseTag], fallback: EdgeCaseEncoder) -> EdgeCaseEncoder:
        def wrap(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:
            potential_encoders = set()
            for tag in tags:
                if tag in edge_cases_encoders:
                    potential_encoders.update(edge_cases_encoders[tag])
                else:
                    print(f"warning: unknown tag '{tag}'")

            options = [enc for appl, enc in potential_encoders if appl(typ)]

            # If no tags can be found, we try the fallback, and route the fallback back to this encoder for deeper use.
            if len(options) == 0:
                return fallback(ann.annotate('_fallback_'), typ, rng, wrap)

            selected_ee = rng.choice(options)
            return selected_ee(ann.annotate('_random_tagged_'), typ, rng, wrap)
        return wrap

    def ee_chain(starting_ee: EdgeCaseEncoder, next_ee) -> EdgeCaseEncoder:
        def wrap(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:
            return starting_ee(ann, typ, rng, next_ee)
        return wrap

    def ee_with_preference(appl: EdgeCaseApplicableFn, prefered: EdgeCaseEncoder, otherwise: EdgeCaseEncoder) -> EdgeCaseEncoder:
        def wrap(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:
            if appl(typ):
                return prefered(ann.annotate('_preference_'), typ, rng, wrap)
            else:
                return otherwise(ann.annotate('_otherwise_'), typ, rng, wrap)
        return wrap

    zero_edge_case = random_with_any_of_tags({'zero'}, random_any_ee)
    max_edge_case = random_with_any_of_tags({'max'}, random_any_ee)

    for (appl, enc) in all_encoders:
        if appl(typ):
            for i in range(random_count):
                yield f'random_{i}', ee_chain(enc, random_any_ee)

            for i in range(random_count):
                yield f'random_with_preference_{i}', ee_chain(enc, ee_with_preference(appl, enc, random_any_ee))

            yield f'preference_or_zero', ee_chain(enc, ee_with_preference(appl, enc, zero_edge_case))
            yield f'preference_or_max', ee_chain(enc, ee_with_preference(appl, enc, max_edge_case))


def main():
    for type_name, spec_typ in get_spec_ssz_types():
        for approach_name, edge_case in build_edge_cases(spec_typ, 5):
            print(f"type: {type_name}")
            print(f"approach: {approach_name}")
            rng = Random(str_hash(type_name + '/' + approach_name))
            annotations: PyList[Annotation] = []
            output: bytes = edge_case(Annotator([], annotations.append), spec_typ, rng, edge_case)
            print("edge case annotations:")
            print('\n'.join('- ' + '/'.join(path) for path in annotations))
            print("output:")
            print(output.hex())
        break


if __name__ == "__main__":
    main()
