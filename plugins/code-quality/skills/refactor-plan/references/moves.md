# Catalogue of behaviour-preserving moves

Each move has a precondition, a mechanical procedure and the test that proves it. If a step does not fit one of these shapes, it is probably a behaviour change in disguise.

| Move | When | Procedure | Proof |
|---|---|---|---|
| Rename | A name lies or is vague | IDE or `sed` rename across the repository; update docs | Compile, grep for the old name returns nothing, tests pass |
| Extract function | A block has a comment explaining it, or is duplicated | Copy the block into a new function with the variables it reads as parameters and the ones it writes as return values; replace the block with a call | Tests pass; the new function gets a unit test |
| Inline | A function is called once and adds no name value | Replace the call with the body | Tests pass |
| Extract class or module | A function group shares data or a prefix | Move the group and its data into a new unit; leave delegating wrappers in place, then remove them in a later step | Tests pass after each of the two sub-steps |
| Move | A function lives next to the wrong data | Create it in the new place, call it from the old place, migrate callers, delete the old one | Tests pass at every sub-step |
| Introduce parameter object | Several functions share four or more parameters | Define a small record type; add it as a parameter while keeping the old ones; switch callers; remove the old ones | Tests pass at every sub-step |
| Replace conditional with polymorphism or a table | A `switch` on a type code appears in several places | Add the dispatch table or classes next to the switch; route one case through it; repeat; delete the switch | Tests pass per case |
| Parallel change (expand, migrate, contract) | Changing a signature used in many places | Add the new signature alongside the old; migrate callers one by one; delete the old | Tests pass at every step; both signatures covered during migration |
| Invert dependency | A low-level module imports a high-level one (circular import) | Define an interface or callback in the low-level module; have the high-level module pass its implementation in | Import graph has no cycle; tests pass |
| Split module | A file over roughly 800 lines with distinct groups | Create the new modules; move one group at a time with re-exports from the old location; remove re-exports last | Tests pass after each move |
| Delete dead code | `dead-code-finder` reports it and a grep confirms no dynamic use | Delete; keep the commit separate | Tests pass; grep for the name returns nothing |
| Characterisation test | Code has no tests and must be refactored | Call the code with recorded inputs and assert the recorded outputs | The test fails if the behaviour changes |
