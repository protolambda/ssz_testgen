# SSZ-testgen

Experimental approach to cover more edge-cases in SSZ tests.

## How it works

`EdgeCaseEncoder` is the function type that forms the core of the edge case generation.

Signature: `(ann: Annotator, typ: Type[View], rng: Random, ee: EdgeCaseEncoder) -> bytes:`

This function traverses a type structure, building a test output.
- The `Annotator` reports the annotation paths of all `EdgeCaseEncoder`s that were registered with the `edge_case` decorator.
- The RNG is used to randomize the test contents (each test case has a deterministic seed for reproducibility)
- The `ee` is used to create edge-cases within an object recursively. Some cases may be valid, others not.

The encoders can be composed, decorated and combined in different ways to build interesting edge-case constructions.

All encoders are globally registered, each with a function that can determine if the encoder is applicable to any given SSZ type.

Then, for each spec type (fetched from the `eth2specs` package), 
and possibly other types specifically designed for SSZ testing, a list of edge-cases can be generated.

These edge cases each annotate their traversal, which is collected to better understand how an edge case was constructed.

After running the edge case, the output can be verified against a trusted SSZ implementation, and saved as a test vector.
Or alternatively, different SSZ implementations are compared, to check if they conform in the same way.  


## License

MIT, see [`LICENSE`](./LICENSE) file.
