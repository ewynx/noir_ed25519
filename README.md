# ed25519 in Noir


## Testing

```
nargo test
nargo test --show-output
```

## Printing

```
use dep::std;

let only_for_printing = arr[0];
std::println(f"Some element {only_for_printing}");
```
